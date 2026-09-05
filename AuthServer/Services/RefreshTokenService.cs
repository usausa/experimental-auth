namespace AuthServer.Services;

using System.Globalization;
using System.Security.Cryptography;
using System.Text;

using AuthServer.Database;
using AuthServer.Models;

using Dapper;

using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

// リフレッシュトークンの発行・ローテーション・失効・検査を管理するサービス。
// トークンは SHA-256 ハッシュのみ保存する。source_code_hash で発行元の認可コードを記録し、
// 同じ認可コードから派生したトークン群 (ファミリー) をまとめて失効できるようにする。
public sealed class RefreshTokenService(DbConnectionFactory dbFactory, IOptions<AuthServerOptions> options)
{
    private readonly AuthServerOptions options = options.Value;

    // リフレッシュトークンを発行して DB に保存し、トークン文字列を返す。
    public async Task<string> IssueAsync(string clientId, string userId, string scopes, string? sourceCodeHash)
    {
        var token = GenerateToken();
        var hash = HashToken(token);
        var now = DateTime.UtcNow;
        var expiresAt = now.AddSeconds(options.RefreshTokenLifetimeSeconds);

        await using var connection = dbFactory.OpenConnection();
        await connection.ExecuteAsync("""
            INSERT INTO refresh_tokens
                (token_hash, client_id, user_id, scopes, expires_at, is_revoked, created_at, source_code_hash)
            VALUES
                (@Hash, @ClientId, @UserId, @Scopes, @ExpiresAt, 0, @CreatedAt, @SourceCodeHash)
            """,
            new
            {
                Hash = hash,
                ClientId = clientId,
                UserId = userId,
                Scopes = scopes,
                ExpiresAt = expiresAt.ToString("o", CultureInfo.InvariantCulture),
                CreatedAt = now.ToString("o", CultureInfo.InvariantCulture),
                SourceCodeHash = sourceCodeHash
            });

        return token;
    }

    // リフレッシュトークンを消費し、ローテートする。成功時は情報と新トークンを返す。
    // 失効済みかつ後継トークンが存在するもの (= ローテーション後の旧トークン) の再提示はリプレイと判断し、
    // 同じファミリーのトークンをすべて失効させる (RFC 6749 §10.4 / OAuth 2.1 §4.3.1)。
    public async Task<(RefreshTokenInfo Info, string NewRefreshToken)?> RotateAsync(string token)
    {
        var hash = HashToken(token);
        await using var connection = dbFactory.OpenConnection();

        var row = await connection.QueryFirstOrDefaultAsync<dynamic>("""
            SELECT token_hash, client_id, user_id, scopes, expires_at, is_revoked, replaced_by_token_hash, source_code_hash
            FROM refresh_tokens WHERE token_hash = @Hash
            """, new { Hash = hash });

        if (row is null)
        {
            return null;
        }

        var sourceCodeHash = IsNull((object?)row.source_code_hash) ? null : (string?)row.source_code_hash;

        if ((long)row.is_revoked != 0)
        {
            if (!IsNull((object?)row.replaced_by_token_hash) && (sourceCodeHash is not null))
            {
                await RevokeFamilyAsync(connection, sourceCodeHash);
            }

            return null;
        }

        if (ParseUtc((string)row.expires_at) < DateTime.UtcNow)
        {
            return null;
        }

        // 旧トークンを失効させて新トークンを発行 (ローテーション)。発行元の認可コードは引き継ぐ。
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
                (token_hash, client_id, user_id, scopes, expires_at, is_revoked, created_at, source_code_hash)
            VALUES
                (@Hash, @ClientId, @UserId, @Scopes, @ExpiresAt, 0, @CreatedAt, @SourceCodeHash)
            """,
            new
            {
                Hash = newHash,
                ClientId = (string)row.client_id,
                UserId = (string)row.user_id,
                Scopes = (string)row.scopes,
                ExpiresAt = expiresAt.ToString("o", CultureInfo.InvariantCulture),
                CreatedAt = now.ToString("o", CultureInfo.InvariantCulture),
                SourceCodeHash = sourceCodeHash
            });

        return (new RefreshTokenInfo((string)row.client_id, (string)row.user_id, (string)row.scopes), newToken);
    }

    // 指定クライアントに発行されたトークンを失効させる。該当トークンが存在すれば true (既に失効済みでも true)。
    // 他クライアントのトークンは存在しないものとして扱い、false を返す。
    public async Task<bool> RevokeAsync(string token, string clientId)
    {
        await using var connection = dbFactory.OpenConnection();
        var affected = await connection.ExecuteAsync(
            "UPDATE refresh_tokens SET is_revoked = 1 WHERE token_hash = @Hash AND client_id = @ClientId",
            new { Hash = HashToken(token), ClientId = clientId });
        return affected > 0;
    }

    // 同じ認可コードから派生したトークン群 (ファミリー) をまとめて失効させる。失効した件数を返す。
    public async Task<int> RevokeFamilyAsync(string sourceCodeHash)
    {
        await using var connection = dbFactory.OpenConnection();
        return await RevokeFamilyAsync(connection, sourceCodeHash);
    }

    // トークンの状態を返す (RFC 7662 用)。存在しなければ null。
    public async Task<RefreshTokenIntrospection?> IntrospectAsync(string token)
    {
        await using var connection = dbFactory.OpenConnection();
        var row = await connection.QueryFirstOrDefaultAsync<dynamic>("""
            SELECT client_id, user_id, scopes, expires_at, is_revoked, created_at
            FROM refresh_tokens WHERE token_hash = @Hash
            """, new { Hash = HashToken(token) });

        if (row is null)
        {
            return null;
        }

        var expiresAt = ParseUtc((string)row.expires_at);
        var active = ((long)row.is_revoked == 0) && (expiresAt > DateTime.UtcNow);
        return new RefreshTokenIntrospection(
            (string)row.client_id,
            (string)row.user_id,
            (string)row.scopes,
            ParseUtc((string)row.created_at),
            expiresAt,
            active);
    }

    // 期限切れのトークン (失効済みを含む) を削除する。
    public async Task<int> DeleteExpiredAsync(DateTime now)
    {
        await using var connection = dbFactory.OpenConnection();
        return await connection.ExecuteAsync(
            "DELETE FROM refresh_tokens WHERE expires_at < @Now",
            new { Now = now.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture) });
    }

    private static Task<int> RevokeFamilyAsync(SqliteConnection connection, string sourceCodeHash) =>
        connection.ExecuteAsync(
            "UPDATE refresh_tokens SET is_revoked = 1 WHERE source_code_hash = @Hash AND is_revoked = 0",
            new { Hash = sourceCodeHash });

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

    private static DateTime ParseUtc(string value) =>
        DateTime.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

    private static bool IsNull(object? value) => value is null || value is DBNull;
}

public sealed record RefreshTokenInfo(string ClientId, string UserId, string Scopes);

public sealed record RefreshTokenIntrospection(
    string ClientId,
    string UserId,
    string Scopes,
    DateTime CreatedAt,
    DateTime ExpiresAt,
    bool Active);
