namespace AuthServer.Services;

using System.Globalization;
using System.Security.Cryptography;
using System.Text;

using AuthServer.Database;
using AuthServer.Models;

using Dapper;

using Microsoft.Extensions.Options;

// Device Authorization Grant (RFC 8628) のデバイスコード / ユーザーコードを管理する。
// device_code は SHA-256 ハッシュのみ保存する。user_code は RFC 8628 §6.1 が推奨する base20 文字集合
// (BCDFGHJKLMNPQRSTVWXZ) 8 文字で、表示時は XXXX-XXXX、保存・照合時はハイフンを除いた大文字で扱う。
// 状態遷移: pending → authorized → consumed (トークン発行済み) / pending → denied。期限切れは expires_at で判定する。
public sealed class DeviceCodeService(DbConnectionFactory dbFactory, IOptions<AuthServerOptions> options)
{
    private const string UserCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ";
    private const int UserCodeLength = 8;

    private readonly AuthServerOptions options = options.Value;

    // デバイスコードとユーザーコードを発行する。
    public async Task<DeviceAuthorization> IssueAsync(string clientId, string scopes)
    {
        var deviceCode = Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var now = DateTime.UtcNow;
        var expiresAt = now.AddSeconds(options.DeviceCodeLifetimeSeconds);

        await using var connection = dbFactory.OpenConnection();

        // user_code は UNIQUE。衝突はほぼ起きない (20^8) が、念のため数回リトライする
        string userCode;
        var attempt = 0;
        do
        {
            userCode = GenerateUserCode();
            attempt++;
        }
        while ((attempt < 5) && (await connection.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM device_codes WHERE user_code = @UserCode", new { UserCode = userCode }) > 0));

        await connection.ExecuteAsync("""
            INSERT INTO device_codes
                (device_code_hash, user_code, client_id, scopes, user_id, status, expires_at, last_polled_at, poll_interval, created_at)
            VALUES
                (@Hash, @UserCode, @ClientId, @Scopes, NULL, 'pending', @ExpiresAt, NULL, @Interval, @CreatedAt)
            """,
            new
            {
                Hash = Hash(deviceCode),
                UserCode = userCode,
                ClientId = clientId,
                Scopes = scopes,
                ExpiresAt = Format(expiresAt),
                Interval = options.DeviceCodePollIntervalSeconds,
                CreatedAt = Format(now)
            });

        return new DeviceAuthorization(deviceCode, FormatUserCode(userCode), options.DeviceCodeLifetimeSeconds, options.DeviceCodePollIntervalSeconds);
    }

    // ユーザーコードで承認待ちの要求を探す (承認画面の表示用)。見つからない・期限切れ・処理済みなら null。
    public async Task<DeviceCodeRecord?> FindPendingByUserCodeAsync(string userCodeInput)
    {
        var record = await FindByUserCodeAsync(NormalizeUserCode(userCodeInput));
        if ((record is null) || (record.Status != "pending") || (record.ExpiresAt <= DateTime.UtcNow))
        {
            return null;
        }

        return record;
    }

    // ユーザーが承認する。承認時刻は ID Token の auth_time になる。
    public Task<DeviceApprovalResult> ApproveAsync(string userCodeInput, string userId) =>
        DecideAsync(userCodeInput, "authorized", userId);

    // ユーザーが拒否する。
    public Task<DeviceApprovalResult> DenyAsync(string userCodeInput) =>
        DecideAsync(userCodeInput, "denied", null);

    // トークンエンドポイントからのポーリング (RFC 8628 §3.4 / §3.5)。
    // 承認済みなら一度だけ Authorized を返し、状態を consumed にする (デバイスコードのワンタイム性)。
    public async Task<DevicePollResult> PollAsync(string deviceCode, string clientId)
    {
        var hash = Hash(deviceCode);
        await using var connection = dbFactory.OpenConnection();

        var row = await connection.QueryFirstOrDefaultAsync<dynamic>("""
            SELECT device_code_hash, user_code, client_id, scopes, user_id, status, expires_at, last_polled_at, poll_interval, authorized_at
            FROM device_codes WHERE device_code_hash = @Hash
            """, new { Hash = hash });

        if ((row is null) || !String.Equals((string)row.client_id, clientId, StringComparison.Ordinal))
        {
            return new DevicePollResult(DevicePollStatus.NotFound, null);
        }

        var now = DateTime.UtcNow;
        var record = ToRecord(row);

        if (record.Status == "consumed")
        {
            return new DevicePollResult(DevicePollStatus.NotFound, null);
        }

        if (record.ExpiresAt <= now)
        {
            return new DevicePollResult(DevicePollStatus.Expired, null);
        }

        // ポーリング間隔の強制: 前回のポーリングから interval 秒未満なら slow_down
        var lastPolled = IsNull((object?)row.last_polled_at) ? (DateTime?)null : ParseUtc((string)row.last_polled_at);
        var interval = (int)(long)row.poll_interval;
        await connection.ExecuteAsync(
            "UPDATE device_codes SET last_polled_at = @Now WHERE device_code_hash = @Hash",
            new { Now = Format(now), Hash = hash });
        if ((lastPolled is not null) && ((now - lastPolled.Value).TotalSeconds < interval))
        {
            return new DevicePollResult(DevicePollStatus.SlowDown, null);
        }

        switch (record.Status)
        {
            case "denied":
                return new DevicePollResult(DevicePollStatus.Denied, null);
            case "authorized":
            {
                // 同時ポーリングで二重発行しないよう、authorized → consumed の遷移が成功した要求だけがトークンを得る
                var affected = await connection.ExecuteAsync(
                    "UPDATE device_codes SET status = 'consumed' WHERE device_code_hash = @Hash AND status = 'authorized'",
                    new { Hash = hash });
                return affected == 1
                    ? new DevicePollResult(DevicePollStatus.Authorized, record)
                    : new DevicePollResult(DevicePollStatus.NotFound, null);
            }

            default:
                return new DevicePollResult(DevicePollStatus.Pending, null);
        }
    }

    // 期限切れのデバイスコード (状態を問わない) を削除する。
    public async Task<int> DeleteExpiredAsync(DateTime now)
    {
        await using var connection = dbFactory.OpenConnection();
        return await connection.ExecuteAsync(
            "DELETE FROM device_codes WHERE expires_at < @Now",
            new { Now = Format(now) });
    }

    // ユーザー入力を保存形式に正規化する: 大文字化し、英字以外 (ハイフン・空白) を除く
    public static string NormalizeUserCode(string input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var builder = new StringBuilder(input.Length);
        foreach (var c in input.ToUpperInvariant())
        {
            if (Char.IsAsciiLetter(c))
            {
                builder.Append(c);
            }
        }

        return builder.ToString();
    }

    private async Task<DeviceApprovalResult> DecideAsync(string userCodeInput, string newStatus, string? userId)
    {
        var userCode = NormalizeUserCode(userCodeInput);
        var record = await FindByUserCodeAsync(userCode);
        if (record is null)
        {
            return DeviceApprovalResult.NotFound;
        }

        if (record.ExpiresAt <= DateTime.UtcNow)
        {
            return DeviceApprovalResult.Expired;
        }

        if (record.Status != "pending")
        {
            return DeviceApprovalResult.AlreadyDecided;
        }

        await using var connection = dbFactory.OpenConnection();
        var affected = await connection.ExecuteAsync("""
            UPDATE device_codes SET status = @Status, user_id = @UserId, authorized_at = @Now
            WHERE user_code = @UserCode AND status = 'pending'
            """,
            new { Status = newStatus, UserId = userId, Now = Format(DateTime.UtcNow), UserCode = userCode });

        if (affected == 0)
        {
            return DeviceApprovalResult.AlreadyDecided;
        }

        return newStatus == "authorized" ? DeviceApprovalResult.Approved : DeviceApprovalResult.Denied;
    }

    private async Task<DeviceCodeRecord?> FindByUserCodeAsync(string userCode)
    {
        await using var connection = dbFactory.OpenConnection();
        var row = await connection.QueryFirstOrDefaultAsync<dynamic>("""
            SELECT device_code_hash, user_code, client_id, scopes, user_id, status, expires_at, last_polled_at, poll_interval, authorized_at
            FROM device_codes WHERE user_code = @UserCode
            """, new { UserCode = userCode });
        return row is null ? null : ToRecord(row);
    }

    private static DeviceCodeRecord ToRecord(dynamic row) => new(
        (string)row.device_code_hash,
        (string)row.client_id,
        (string)row.scopes,
        IsNull((object?)row.user_id) ? null : (string?)row.user_id,
        (string)row.status,
        ParseUtc((string)row.expires_at),
        IsNull((object?)row.authorized_at) ? null : ParseUtc((string)row.authorized_at));

    private static string GenerateUserCode()
    {
        var chars = new char[UserCodeLength];
        for (var i = 0; i < chars.Length; i++)
        {
            chars[i] = UserCodeAlphabet[RandomNumberGenerator.GetInt32(UserCodeAlphabet.Length)];
        }

        return new string(chars);
    }

    private static string FormatUserCode(string userCode) =>
        userCode.Length == UserCodeLength ? $"{userCode[..4]}-{userCode[4..]}" : userCode;

    private static string Hash(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string Format(DateTime value) => value.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);

    private static DateTime ParseUtc(string value) => DateTime.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

    private static bool IsNull(object? value) => value is null || value is DBNull;
}

public sealed record DeviceAuthorization(string DeviceCode, string UserCode, int ExpiresInSeconds, int IntervalSeconds);

public sealed record DeviceCodeRecord(
    string DeviceCodeHash,
    string ClientId,
    string Scopes,
    string? UserId,
    string Status,
    DateTime ExpiresAt,
    DateTime? AuthorizedAt);

public enum DeviceApprovalResult
{
    Approved,
    Denied,
    NotFound,
    Expired,
    AlreadyDecided
}

public enum DevicePollStatus
{
    Authorized,
    Pending,
    SlowDown,
    Denied,
    Expired,
    NotFound
}

public sealed record DevicePollResult(DevicePollStatus Status, DeviceCodeRecord? Record);
