namespace AuthServer.Services;

using System.Globalization;
using System.Text;

using AuthServer.Database;
using AuthServer.Models;

using Dapper;

// 監査ログ。認証・トークン発行・失効・鍵操作・管理操作を永続化し、管理画面 (/audit-logs) で参照する。
// 記録に失敗しても本処理は止めない (呼び出し側で await するが、DB 障害時は例外がそのまま伝播する)。
public sealed class AuditLogService(DbConnectionFactory dbFactory)
{
    private const string SelectColumns = """
        id AS Id, occurred_at AS OccurredAt, event AS Event, outcome AS Outcome,
        client_id AS ClientId, user_id AS UserId, subject AS Subject, ip_address AS IpAddress, detail AS Detail
        """;

    public async Task RecordAsync(AuditEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        await using var connection = dbFactory.OpenConnection();
        await connection.ExecuteAsync("""
            INSERT INTO audit_logs (occurred_at, event, outcome, client_id, user_id, subject, ip_address, detail)
            VALUES (@OccurredAt, @Event, @Outcome, @ClientId, @UserId, @Subject, @IpAddress, @Detail)
            """,
            new
            {
                OccurredAt = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture),
                entry.Event,
                entry.Outcome,
                entry.ClientId,
                entry.UserId,
                entry.Subject,
                entry.IpAddress,
                entry.Detail
            });
    }

    // 新しい順に最大 limit 件。フィルターは AND 条件。Search は user_id / subject / detail の部分一致。
    public async Task<IReadOnlyList<AuditLog>> QueryAsync(AuditLogFilter filter, int limit)
    {
        ArgumentNullException.ThrowIfNull(filter);
        var sql = new StringBuilder($"SELECT {SelectColumns} FROM audit_logs WHERE 1 = 1");
        if (!String.IsNullOrEmpty(filter.Event))
        {
            sql.Append(" AND event = @Event");
        }

        if (!String.IsNullOrEmpty(filter.Outcome))
        {
            sql.Append(" AND outcome = @Outcome");
        }

        if (!String.IsNullOrEmpty(filter.ClientId))
        {
            sql.Append(" AND client_id = @ClientId");
        }

        if (!String.IsNullOrEmpty(filter.Search))
        {
            sql.Append(" AND (user_id LIKE @Search OR subject LIKE @Search OR detail LIKE @Search)");
        }

        sql.Append(" ORDER BY id DESC LIMIT @Limit");

        await using var connection = dbFactory.OpenConnection();
        var rows = await connection.QueryAsync<AuditLog>(
            sql.ToString(),
            new
            {
                filter.Event,
                filter.Outcome,
                filter.ClientId,
                Search = String.IsNullOrEmpty(filter.Search) ? null : "%" + filter.Search + "%",
                Limit = limit
            });
        return rows.ToList();
    }

    public async Task<IReadOnlyList<string>> QueryEventTypesAsync()
    {
        await using var connection = dbFactory.OpenConnection();
        var rows = await connection.QueryAsync<string>("SELECT DISTINCT event FROM audit_logs ORDER BY event");
        return rows.ToList();
    }

    public async Task<int> DeleteOlderThanAsync(DateTime cutoff)
    {
        await using var connection = dbFactory.OpenConnection();
        return await connection.ExecuteAsync(
            "DELETE FROM audit_logs WHERE occurred_at < @Cutoff",
            new { Cutoff = cutoff.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture) });
    }
}

public static class AuditOutcome
{
    public const string Success = "success";
    public const string Failure = "failure";
    public const string Info = "info";
}

// イベント名。管理画面のフィルターにそのまま出るので、名前は安定させる。
public static class AuditEvents
{
    public const string ClientAuth = "client_auth";
    public const string TokenIssued = "token_issued";
    public const string TokenDenied = "token_denied";
    public const string Authorize = "authorize";
    public const string DeviceAuthorize = "device_authorize";
    public const string DeviceApproved = "device_approved";
    public const string DeviceDenied = "device_denied";
    public const string TokenRevoked = "token_revoked";
    public const string ReplayDetected = "replay_detected";
    public const string KeyRotated = "key_rotated";
    public const string KeyScheduled = "key_scheduled";
    public const string KeyPromoted = "key_promoted";
    public const string UserCreated = "user_created";
    public const string UserUpdated = "user_updated";
    public const string UserDeleted = "user_deleted";
    public const string UserPasswordChanged = "user_password_changed";
    public const string ResourceServerChanged = "resource_server_changed";
    public const string ClaimDefinitionChanged = "claim_definition_changed";
    public const string UserClaimsChanged = "user_claims_changed";
}

public sealed record AuditEntry(
    string Event,
    string Outcome,
    string? ClientId = null,
    string? UserId = null,
    string? Subject = null,
    string? IpAddress = null,
    string? Detail = null);

public sealed record AuditLogFilter(string? Event, string? Outcome, string? ClientId, string? Search);
