namespace AuthServer.Services;

using System.Globalization;
using System.Security.Cryptography;
using System.Text;

using AuthServer.Database;
using AuthServer.Models;

using Dapper;

using Microsoft.Extensions.Options;

// リフレッシュトークンの発行・検証・消費を管理するサービス。
public sealed class RefreshTokenService(DbConnectionFactory dbFactory, IOptions<AuthServerOptions> options)
{
    private readonly AuthServerOptions options = options.Value;

    // リフレッシュトークンを発行して DB に保存し、トークン文字列を返す。
    public async Task<string> IssueAsync(string clientId, string userId, string scopes)
    {
        var token = GenerateToken();
        var hash = HashToken(token);
        var now = DateTime.UtcNow;
        var expiresAt = now.AddSeconds(options.RefreshTokenLifetimeSeconds);

        await using var connection = dbFactory.OpenConnection();
        await connection.ExecuteAsync("""
            INSERT INTO refresh_tokens
                (token_hash, client_id, user_id, scopes, expires_at, is_revoked, created_at)
            VALUES
                (@Hash, @ClientId, @UserId, @Scopes, @ExpiresAt, 0, @CreatedAt)
            """,
            new
            {
                Hash = hash,
                ClientId = clientId,
                UserId = userId,
                Scopes = scopes,
                ExpiresAt = expiresAt.ToString("o", CultureInfo.InvariantCulture),
                CreatedAt = now.ToString("o", CultureInfo.InvariantCulture)
            });

        return token;
    }

    // リフレッシュトークンを消費し、ローテートする。成功時は情報を返す。
    public async Task<(RefreshTokenInfo Info, string NewRefreshToken)?> RotateAsync(string token)
    {
        var hash = HashToken(token);
        await using var connection = dbFactory.OpenConnection();

        var row = await connection.QueryFirstOrDefaultAsync<dynamic>("""
            SELECT token_hash, client_id, user_id, scopes, expires_at, is_revoked
            FROM refresh_tokens WHERE token_hash = @Hash
            """, new { Hash = hash });

        if (row is null)
        {
            return null;
        }

        if ((long)row.is_revoked != 0)
        {
            return null;
        }

        if (DateTime.Parse((string)row.expires_at, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind) < DateTime.UtcNow)
        {
            return null;
        }

        // 旧トークンを失効させて新トークンを発行(ローテーション)
        var newToken = GenerateToken();
        var newHash = HashToken(newToken);
        var now = DateTime.UtcNow;
        var expiresAt = now.AddSeconds(options.RefreshTokenLifetimeSeconds);

        await connection.ExecuteAsync("""
            UPDATE refresh_tokens SET is_revoked = 1, replaced_by_token_hash = @NewHash
            WHERE token_hash = @OldHash
            """, new { NewHash = newHash, OldHash = hash });

        await connection.ExecuteAsync("""
            INSERT INTO refresh_tokens
                (token_hash, client_id, user_id, scopes, expires_at, is_revoked, created_at)
            VALUES
                (@Hash, @ClientId, @UserId, @Scopes, @ExpiresAt, 0, @CreatedAt)
            """,
            new
            {
                Hash = newHash,
                ClientId = (string)row.client_id,
                UserId = (string)row.user_id,
                Scopes = (string)row.scopes,
                ExpiresAt = expiresAt.ToString("o", CultureInfo.InvariantCulture),
                CreatedAt = now.ToString("o", CultureInfo.InvariantCulture)
            });

        return (new RefreshTokenInfo((string)row.client_id, (string)row.user_id, (string)row.scopes), newToken);
    }

    private static string GenerateToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static string HashToken(string token)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return Convert.ToHexStringLower(bytes);
    }
}

public sealed record RefreshTokenInfo(string ClientId, string UserId, string Scopes);
