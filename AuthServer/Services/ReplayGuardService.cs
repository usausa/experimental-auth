namespace AuthServer.Services;

using System.Globalization;

using AuthServer.Database;

using Dapper;

// 一回限りの値 (クライアントアサーションの jti、認可要求の nonce など) を記録し、再提示 (リプレイ) を検知する。
// 値は kind ごとに一意。expires_at にはその値を含むトークンが失効する時刻を入れ、期限を過ぎたエントリは保守ジョブが削除する。
public sealed class ReplayGuardService(DbConnectionFactory dbFactory)
{
    public const string ClientAssertionJti = "client_assertion_jti";
    public const string AuthorizationNonce = "nonce";

    // 初出なら記録して true を返す。既に記録済み (= リプレイ) なら false。
    public async Task<bool> TryRegisterAsync(string kind, string value, string? clientId, DateTime expiresAt)
    {
        await using var connection = dbFactory.OpenConnection();
        var inserted = await connection.ExecuteAsync("""
            INSERT OR IGNORE INTO replay_guard (kind, value, client_id, expires_at)
            VALUES (@Kind, @Value, @ClientId, @ExpiresAt)
            """,
            new
            {
                Kind = kind,
                Value = value,
                ClientId = clientId,
                ExpiresAt = expiresAt.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture)
            });
        return inserted == 1;
    }

    public async Task<int> DeleteExpiredAsync(DateTime now)
    {
        await using var connection = dbFactory.OpenConnection();
        return await connection.ExecuteAsync(
            "DELETE FROM replay_guard WHERE expires_at < @Now",
            new { Now = now.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture) });
    }
}
