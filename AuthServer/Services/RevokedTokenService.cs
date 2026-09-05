namespace AuthServer.Services;

using System.Globalization;

using AuthServer.Database;

using Dapper;

// 失効済みトークンの JTI を管理する (RFC 7009)。
// アクセストークンは自己完結型の JWT のため DB を書き換えて無効化できない。代わりに JTI を失効リストへ登録し、
// AuthServer 自身のエンドポイント (UserInfo / Introspection) で照合する。
// ResourceServer はオフライン検証のみで失効リストを参照しないため、アクセストークンの失効は有効期限まで反映されない (SPEC §6.5 方式 3)。
public sealed class RevokedTokenService(DbConnectionFactory dbFactory)
{
    public async Task RevokeAsync(string jti, string tokenType, DateTime expiresAt)
    {
        await using var connection = dbFactory.OpenConnection();
        await connection.ExecuteAsync("""
            INSERT OR IGNORE INTO revoked_tokens (jti, token_type, revoked_at, expires_at)
            VALUES (@Jti, @TokenType, @RevokedAt, @ExpiresAt)
            """,
            new
            {
                Jti = jti,
                TokenType = tokenType,
                RevokedAt = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture),
                ExpiresAt = expiresAt.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture)
            });
    }

    public async Task<bool> IsRevokedAsync(string jti)
    {
        await using var connection = dbFactory.OpenConnection();
        var count = await connection.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM revoked_tokens WHERE jti = @Jti",
            new { Jti = jti });
        return count > 0;
    }

    // 有効期限を過ぎた (= もはや署名検証を通らない) 失効エントリを削除する。
    public async Task<int> DeleteExpiredAsync(DateTime now)
    {
        await using var connection = dbFactory.OpenConnection();
        return await connection.ExecuteAsync(
            "DELETE FROM revoked_tokens WHERE expires_at < @Now",
            new { Now = now.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture) });
    }
}
