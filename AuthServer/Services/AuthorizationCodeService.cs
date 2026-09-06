namespace AuthServer.Services;

using System.Globalization;
using System.Security.Cryptography;
using System.Text;

using AuthServer.Database;
using AuthServer.Models;

using Dapper;

using Microsoft.Extensions.Options;

#pragma warning disable CA1054
// 認可コードの発行・検証・消費を管理するサービス。
public sealed class AuthorizationCodeService(DbConnectionFactory dbFactory, IOptions<AuthServerOptions> options)
{
    private readonly AuthServerOptions options = options.Value;

    // 認可コードを発行して DB に保存し、コード文字列を返す。
    public async Task<string> IssueAsync(
        string clientId,
        string userId,
        string redirectUri,
        string scopes,
        string? codeChallenge,
        string? codeChallengeMethod,
        string? nonce,
        string? state)
    {
        var code = GenerateCode();
        var hash = HashCode(code);
        var now = DateTime.UtcNow;
        var expiresAt = now.AddSeconds(options.AuthorizationCodeLifetimeSeconds);

        await using var connection = dbFactory.OpenConnection();
        await connection.ExecuteAsync("""
            INSERT INTO authorization_codes
                (code_hash, client_id, user_id, redirect_uri, scopes,
                 code_challenge, code_challenge_method, nonce, state, expires_at, created_at)
            VALUES
                (@CodeHash, @ClientId, @UserId, @RedirectUri, @Scopes,
                 @CodeChallenge, @CodeChallengeMethod, @Nonce, @State, @ExpiresAt, @CreatedAt)
            """,
            new
            {
                CodeHash = hash,
                ClientId = clientId,
                UserId = userId,
                RedirectUri = redirectUri,
                Scopes = scopes,
                CodeChallenge = codeChallenge,
                CodeChallengeMethod = codeChallengeMethod,
                Nonce = nonce,
                State = state,
                ExpiresAt = expiresAt.ToString("o", CultureInfo.InvariantCulture),
                CreatedAt = now.ToString("o", CultureInfo.InvariantCulture)
            });

        return code;
    }

    // 認可コードを消費する。ワンタイム性は DELETE ではなく consumed_at で表現し、
    // 消費済みコードの再提示 (= 漏洩の疑い) を Reused として呼び出し側に知らせる (RFC 6749 §4.1.2)。
    public async Task<AuthorizationCodeConsumeResult> ConsumeAsync(string code)
    {
        var hash = HashCode(code);
        await using var connection = dbFactory.OpenConnection();

        var row = await connection.QueryFirstOrDefaultAsync<dynamic>("""
            SELECT client_id, user_id, redirect_uri, scopes,
                   code_challenge, code_challenge_method, nonce, expires_at, created_at, consumed_at
            FROM authorization_codes WHERE code_hash = @Hash
            """, new { Hash = hash });

        if (row is null)
        {
            return new AuthorizationCodeConsumeResult(AuthorizationCodeConsumeStatus.NotFound, null);
        }

        var info = new AuthorizationCodeInfo(
            (string)row.client_id,
            (string)row.user_id,
            (string)row.redirect_uri,
            (string)row.scopes,
            IsNull((object?)row.code_challenge) ? null : (string?)row.code_challenge,
            IsNull((object?)row.code_challenge_method) ? null : (string?)row.code_challenge_method,
            IsNull((object?)row.nonce) ? null : (string?)row.nonce,
            ParseUtc((string)row.created_at),
            hash);

        if (!IsNull((object?)row.consumed_at))
        {
            return new AuthorizationCodeConsumeResult(AuthorizationCodeConsumeStatus.Reused, info);
        }

        // 消費 (ワンタイム)
        await connection.ExecuteAsync(
            "UPDATE authorization_codes SET consumed_at = @Now WHERE code_hash = @Hash",
            new { Now = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture), Hash = hash });

        if (ParseUtc((string)row.expires_at) < DateTime.UtcNow)
        {
            return new AuthorizationCodeConsumeResult(AuthorizationCodeConsumeStatus.Expired, info);
        }

        return new AuthorizationCodeConsumeResult(AuthorizationCodeConsumeStatus.Success, info);
    }

    // 期限切れの認可コード (消費済みを含む) を削除する。
    public async Task<int> DeleteExpiredAsync(DateTime now)
    {
        await using var connection = dbFactory.OpenConnection();
        return await connection.ExecuteAsync(
            "DELETE FROM authorization_codes WHERE expires_at < @Now",
            new { Now = now.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture) });
    }

    // PKCE code_verifier を検証する(S256)。
    public static bool VerifyPkce(string codeChallenge, string codeChallengeMethod, string codeVerifier)
    {
        if (!String.Equals(codeChallengeMethod, "S256", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var bytes = SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier));
        var computed = Base64UrlEncode(bytes);
        return String.Equals(computed, codeChallenge, StringComparison.Ordinal);
    }

    private static string GenerateCode()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Base64UrlEncode(bytes);
    }

    private static string HashCode(string code)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(code));
        return Convert.ToHexStringLower(bytes);
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static DateTime ParseUtc(string value) =>
        DateTime.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

    private static bool IsNull(object? value) => value is null || value is DBNull;
}
#pragma warning restore CA1054

public enum AuthorizationCodeConsumeStatus
{
    Success,
    NotFound,
    Expired,
    Reused
}

public sealed record AuthorizationCodeConsumeResult(AuthorizationCodeConsumeStatus Status, AuthorizationCodeInfo? Info);

#pragma warning disable CA1054
#pragma warning disable CA1056
public sealed record AuthorizationCodeInfo(
    string ClientId,
    string UserId,
    string RedirectUri,
    string Scopes,
    string? CodeChallenge,
    string? CodeChallengeMethod,
    string? Nonce,
    // ユーザー認証時刻。方式 B では資格情報の検証直後にコードを発行するため created_at と一致する (ID Token の auth_time)
    DateTime AuthTime,
    // コードのハッシュ。発行したリフレッシュトークンの source_code_hash に記録し、ファミリー単位の失効に使う
    string CodeHash);
#pragma warning restore CA1056
#pragma warning restore CA1054
