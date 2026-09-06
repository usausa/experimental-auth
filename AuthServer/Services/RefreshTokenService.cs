namespace AuthServer.Services;

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using AuthServer.Database;
using AuthServer.Models;

using Dapper;

using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

// リフレッシュトークンの発行・ローテーション・失効・検査を管理するサービス。
// トークンは SHA-256 ハッシュのみ保存する。source_code_hash で発行元の認可コード (またはデバイスコード) を記録し、
// 同じコードから派生したトークン群 (ファミリー) をまとめて失効できるようにする。
// 有効期限は 2 段構え: expires_at はローテーションごとに延びる無操作タイムアウト、
// family_expires_at は最初の認可からの絶対期限でローテーションでは延びない。
public sealed class RefreshTokenService(DbConnectionFactory dbFactory, IOptions<AuthServerOptions> options)
{
    private readonly AuthServerOptions options = options.Value;

    // リフレッシュトークンを発行して DB に保存し、トークン文字列を返す。
    // audiences は発行時に付与した audience。refresh 時に resource を省略した場合に同じ audience を維持する (RFC 8707 §2.2)。
    public async Task<string> IssueAsync(string clientId, string userId, string scopes, string? sourceCodeHash, IReadOnlyList<string>? audiences = null)
    {
        var token = GenerateToken();
        var hash = HashToken(token);
        var now = DateTime.UtcNow;
        var familyExpiresAt = now.AddSeconds(options.RefreshTokenAbsoluteLifetimeSeconds);
        var expiresAt = Min(now.AddSeconds(options.RefreshTokenLifetimeSeconds), familyExpiresAt);

        await using var connection = dbFactory.OpenConnection();
        await connection.ExecuteAsync("""
            INSERT INTO refresh_tokens
                (token_hash, client_id, user_id, scopes, expires_at, is_revoked, created_at, source_code_hash, family_expires_at, audiences)
            VALUES
                (@Hash, @ClientId, @UserId, @Scopes, @ExpiresAt, 0, @CreatedAt, @SourceCodeHash, @FamilyExpiresAt, @Audiences)
            """,
            new
            {
                Hash = hash,
                ClientId = clientId,
                UserId = userId,
                Scopes = scopes,
                ExpiresAt = Format(expiresAt),
                CreatedAt = Format(now),
                SourceCodeHash = sourceCodeHash,
                FamilyExpiresAt = Format(familyExpiresAt),
                Audiences = audiences is null ? null : JsonSerializer.Serialize(audiences)
            });

        return token;
    }

    // リフレッシュトークンを消費し、ローテートする。成功時は情報と新トークンを返す。
    // 失効済みかつ後継トークンが存在するもの (= ローテーション後の旧トークン) の再提示はリプレイと判断し、
    // 同じファミリーのトークンをすべて失効させる (RFC 6749 §10.4 / OAuth 2.1 §4.3.1)。
    // 新トークンの有効期限は「無操作タイムアウト」と「ファミリー絶対期限」の早い方。
    public async Task<(RefreshTokenInfo Info, string NewRefreshToken)?> RotateAsync(string token)
    {
        var hash = HashToken(token);
        await using var connection = dbFactory.OpenConnection();

        var row = await connection.QueryFirstOrDefaultAsync<dynamic>("""
            SELECT token_hash, client_id, user_id, scopes, expires_at, is_revoked, replaced_by_token_hash,
                   source_code_hash, family_expires_at, audiences
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

        var now = DateTime.UtcNow;
        if (ParseUtc((string)row.expires_at) < now)
        {
            return null;
        }

        // v4 以前に発行されたトークンは family_expires_at を持たない。その場合はここで絶対期限を起算する。
        var familyExpiresAt = IsNull((object?)row.family_expires_at)
            ? now.AddSeconds(options.RefreshTokenAbsoluteLifetimeSeconds)
            : ParseUtc((string)row.family_expires_at);
        if (familyExpiresAt <= now)
        {
            return null;
        }

        var audiencesJson = IsNull((object?)row.audiences) ? null : (string?)row.audiences;
        var audiences = audiencesJson is null ? [] : JsonSerializer.Deserialize<string[]>(audiencesJson) ?? [];

        // 旧トークンを失効させて新トークンを発行 (ローテーション)。発行元コード・絶対期限・audience は引き継ぐ。
        var newToken = GenerateToken();
        var newHash = HashToken(newToken);
        var expiresAt = Min(now.AddSeconds(options.RefreshTokenLifetimeSeconds), familyExpiresAt);

        await connection.ExecuteAsync("""
            UPDATE refresh_tokens SET is_revoked = 1, replaced_by_token_hash = @NewHash
            WHERE token_hash = @OldHash
            """, new { NewHash = newHash, OldHash = hash });

        await connection.ExecuteAsync("""
            INSERT INTO refresh_tokens
                (token_hash, client_id, user_id, scopes, expires_at, is_revoked, created_at, source_code_hash, family_expires_at, audiences)
            VALUES
                (@Hash, @ClientId, @UserId, @Scopes, @ExpiresAt, 0, @CreatedAt, @SourceCodeHash, @FamilyExpiresAt, @Audiences)
            """,
            new
            {
                Hash = newHash,
                ClientId = (string)row.client_id,
                UserId = (string)row.user_id,
                Scopes = (string)row.scopes,
                ExpiresAt = Format(expiresAt),
                CreatedAt = Format(now),
                SourceCodeHash = sourceCodeHash,
                FamilyExpiresAt = Format(familyExpiresAt),
                Audiences = audiencesJson
            });

        return (new RefreshTokenInfo((string)row.client_id, (string)row.user_id, (string)row.scopes, audiences), newToken);
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

    // 同じコードから派生したトークン群 (ファミリー) をまとめて失効させる。失効した件数を返す。
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
            SELECT client_id, user_id, scopes, expires_at, is_revoked, created_at, family_expires_at
            FROM refresh_tokens WHERE token_hash = @Hash
            """, new { Hash = HashToken(token) });

        if (row is null)
        {
            return null;
        }

        var now = DateTime.UtcNow;
        var expiresAt = ParseUtc((string)row.expires_at);
        var familyAlive = IsNull((object?)row.family_expires_at) || (ParseUtc((string)row.family_expires_at) > now);
        var active = ((long)row.is_revoked == 0) && (expiresAt > now) && familyAlive;
        return new RefreshTokenIntrospection(
            (string)row.client_id,
            (string)row.user_id,
            (string)row.scopes,
            ParseUtc((string)row.created_at),
            expiresAt,
            active);
    }

    // 期限切れのトークン (失効済み・ファミリー期限切れを含む) を削除する。
    public async Task<int> DeleteExpiredAsync(DateTime now)
    {
        await using var connection = dbFactory.OpenConnection();
        return await connection.ExecuteAsync(
            "DELETE FROM refresh_tokens WHERE expires_at < @Now OR (family_expires_at IS NOT NULL AND family_expires_at < @Now)",
            new { Now = Format(now) });
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

    private static string Format(DateTime value) =>
        value.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);

    private static DateTime ParseUtc(string value) =>
        DateTime.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

    private static DateTime Min(DateTime a, DateTime b) => a < b ? a : b;

    private static bool IsNull(object? value) => value is null || value is DBNull;
}

public sealed record RefreshTokenInfo(string ClientId, string UserId, string Scopes, IReadOnlyList<string> Audiences);

public sealed record RefreshTokenIntrospection(
    string ClientId,
    string UserId,
    string Scopes,
    DateTime CreatedAt,
    DateTime ExpiresAt,
    bool Active);
