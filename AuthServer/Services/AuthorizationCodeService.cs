namespace AuthServer.Services;

using System.Globalization;
using System.Security.Cryptography;
using System.Text;

using AuthServer.Database;

using Dapper;

#pragma warning disable CA1054
// 認可コードの発行・検証・消費を管理するサービス。
public sealed class AuthorizationCodeService(DbConnectionFactory dbFactory)
{
    private const int CodeLifetimeSeconds = 120;

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
        var expiresAt = now.AddSeconds(CodeLifetimeSeconds);

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

    // 認可コードを消費する。成功時は情報を返し、コードを DB から削除する。失敗時は null。
    public async Task<AuthorizationCodeInfo?> ConsumeAsync(string code)
    {
        var hash = HashCode(code);
        await using var connection = dbFactory.OpenConnection();

        var row = await connection.QueryFirstOrDefaultAsync<dynamic>("""
            SELECT client_id, user_id, redirect_uri, scopes,
                   code_challenge, code_challenge_method, nonce, expires_at
            FROM authorization_codes WHERE code_hash = @Hash
            """, new { Hash = hash });

        if (row is null)
        {
            return null;
        }

        // 消費(ワンタイム)
        await connection.ExecuteAsync(
            "DELETE FROM authorization_codes WHERE code_hash = @Hash", new { Hash = hash });

        if (DateTime.Parse((string)row.expires_at, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind) < DateTime.UtcNow)
        {
            return null;
        }

        return new AuthorizationCodeInfo(
            (string)row.client_id,
            (string)row.user_id,
            (string)row.redirect_uri,
            (string)row.scopes,
            row.code_challenge is DBNull ? null : (string?)row.code_challenge,
            row.code_challenge_method is DBNull ? null : (string?)row.code_challenge_method,
            row.nonce is DBNull ? null : (string?)row.nonce);
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
}
#pragma warning restore CA1054

#pragma warning disable CA1054
#pragma warning disable CA1056
public sealed record AuthorizationCodeInfo(
    string ClientId,
    string UserId,
    string RedirectUri,
    string Scopes,
    string? CodeChallenge,
    string? CodeChallengeMethod,
    string? Nonce);
#pragma warning restore CA1056
#pragma warning restore CA1054
