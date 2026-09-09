namespace AuthServer.Tests.Infrastructure;

using System.Buffers.Text;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

// OAuth 2.0 / OIDC エンドポイントを叩くためのヘルパー。seed のフィクスチャ (test-client / test-webapp / test-device / test-jwt-client / alice) を前提にする。
internal static class Oauth
{
    public const string Issuer = "https://localhost:5080";
    public const string DefaultAudience = "https://localhost:5180";
    public const string RedirectTarget = "http://localhost:5173/callback";
    public const string JwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    public const string DeviceGrantType = "urn:ietf:params:oauth:grant-type:device_code";

    public const string TokenPath = "/connect/token";
    public const string AuthorizePath = "/connect/authorize";
    public const string UserInfoPath = "/connect/userinfo";
    public const string RevokePath = "/connect/revoke";
    public const string IntrospectPath = "/connect/introspect";
    public const string DeviceAuthorizePath = "/connect/device/authorize";
    public const string SessionPath = "/account/session";
    public const string DiscoveryPath = "/.well-known/openid-configuration";
    public const string JwksPath = "/.well-known/jwks.json";

    // DataSeeder が登録する test-jwt-client の公開鍵に対応する開発用の秘密鍵 (TestClient と同じフィクスチャ)
    public const string DevPrivateJwk =
        """{"kty":"EC","crv":"P-256","kid":"test-jwt-client-key-1","use":"sig","alg":"ES256","x":"fn5umSHzhOJPWsYiRUym3idqsL_pMRPjBF6inYrlpMc","y":"Rm1bMhzItJAwBUes0bYl089scqmxWnE1_hIximqboLk","d":"MZkSyMv8Q__95Azty5o10r5Ffr5nczogA-OOkrPZwj8"}""";

    public static Dictionary<string, string> Form(params (string Key, string Value)[] fields) =>
        fields.ToDictionary(f => f.Key, f => f.Value, StringComparer.Ordinal);

    public static async Task<OauthResponse> PostFormAsync(
        HttpClient client, string path, IEnumerable<KeyValuePair<string, string>> form, Action<HttpRequestMessage>? configure = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(path, UriKind.Relative));
        request.Content = new FormUrlEncodedContent(form);
        configure?.Invoke(request);
        using var response = await client.SendAsync(request).ConfigureAwait(false);
        return await OauthResponse.FromAsync(response).ConfigureAwait(false);
    }

    public static async Task<OauthResponse> GetAsync(HttpClient client, string path, string? bearerToken = null, Action<HttpRequestMessage>? configure = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(path, UriKind.Relative));
        if (bearerToken is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);
        }

        configure?.Invoke(request);
        using var response = await client.SendAsync(request).ConfigureAwait(false);
        return await OauthResponse.FromAsync(response).ConfigureAwait(false);
    }

    public static async Task<OauthResponse> SendAsync(HttpClient client, HttpMethod method, string path, Action<HttpRequestMessage>? configure = null)
    {
        using var request = new HttpRequestMessage(method, new Uri(path, UriKind.Relative));
        configure?.Invoke(request);
        using var response = await client.SendAsync(request).ConfigureAwait(false);
        return await OauthResponse.FromAsync(response).ConfigureAwait(false);
    }

    // client_credentials (client_secret_post)
    public static Task<OauthResponse> ClientCredentialsAsync(
        HttpClient client, string clientId = "test-client", string clientSecret = "test-secret", string scope = "api.read",
        params (string Key, string Value)[] extra)
    {
        var form = Form(("grant_type", "client_credentials"), ("client_id", clientId), ("client_secret", clientSecret), ("scope", scope));
        foreach (var (key, value) in extra)
        {
            form[key] = value;
        }

        return PostFormAsync(client, TokenPath, form);
    }

    // 方式 B の認可要求。nonce が null なら送らない
    public static Task<OauthResponse> AuthorizeAsync(
        HttpClient client, string scope, string? nonce, string codeChallenge,
        string username = "alice", string password = "password", string clientId = "test-webapp", string redirectTarget = RedirectTarget,
        params (string Key, string Value)[] extra)
    {
        var form = Form(
            ("response_type", "code"),
            ("client_id", clientId),
            ("redirect_uri", redirectTarget),
            ("scope", scope),
            ("code_challenge", codeChallenge),
            ("code_challenge_method", "S256"),
            ("username", username),
            ("password", password));
        if (nonce is not null)
        {
            form["nonce"] = nonce;
        }

        foreach (var (key, value) in extra)
        {
            form[key] = value;
        }

        return PostFormAsync(client, AuthorizePath, form);
    }

    public static Task<OauthResponse> ExchangeCodeAsync(
        HttpClient client, string code, string codeVerifier, string clientId = "test-webapp", string clientSecret = "webapp-secret",
        params (string Key, string Value)[] extra)
    {
        var form = Form(
            ("grant_type", "authorization_code"),
            ("client_id", clientId),
            ("client_secret", clientSecret),
            ("code", code),
            ("redirect_uri", RedirectTarget),
            ("code_verifier", codeVerifier));
        foreach (var (key, value) in extra)
        {
            form[key] = value;
        }

        return PostFormAsync(client, TokenPath, form);
    }

    // 認可コード取得とトークン交換をまとめて行う。失敗したら Assert で止める
    public static async Task<OauthResponse> AuthorizeAndExchangeAsync(HttpClient client, string scope, params (string Key, string Value)[] tokenExtra)
    {
        var (verifier, challenge) = CreatePkce();
        var authorize = await AuthorizeAsync(client, scope, NewNonce(), challenge).ConfigureAwait(false);
        Assert.Equal(HttpStatusCode.OK, authorize.Status);
        var exchange = await ExchangeCodeAsync(client, authorize.GetString("code")!, verifier, extra: tokenExtra).ConfigureAwait(false);
        Assert.Equal(HttpStatusCode.OK, exchange.Status);
        return exchange;
    }

    public static Task<OauthResponse> RefreshAsync(
        HttpClient client, string refreshToken, string clientId = "test-webapp", string? clientSecret = "webapp-secret",
        params (string Key, string Value)[] extra)
    {
        var form = Form(("grant_type", "refresh_token"), ("client_id", clientId), ("refresh_token", refreshToken));
        if (clientSecret is not null)
        {
            form["client_secret"] = clientSecret;
        }

        foreach (var (key, value) in extra)
        {
            form[key] = value;
        }

        return PostFormAsync(client, TokenPath, form);
    }

    public static Task<OauthResponse> IntrospectAsync(HttpClient client, string token, string? hint = null, string clientId = "test-webapp", string clientSecret = "webapp-secret")
    {
        var form = Form(("client_id", clientId), ("client_secret", clientSecret), ("token", token));
        if (hint is not null)
        {
            form["token_type_hint"] = hint;
        }

        return PostFormAsync(client, IntrospectPath, form);
    }

    public static Task<OauthResponse> RevokeAsync(HttpClient client, string token, string? hint = null, string clientId = "test-webapp", string clientSecret = "webapp-secret")
    {
        var form = Form(("client_id", clientId), ("client_secret", clientSecret), ("token", token));
        if (hint is not null)
        {
            form["token_type_hint"] = hint;
        }

        return PostFormAsync(client, RevokePath, form);
    }

    public static Task<OauthResponse> UserInfoAsync(HttpClient client, string accessToken) => GetAsync(client, UserInfoPath, accessToken);

    public static Task<OauthResponse> PollDeviceAsync(HttpClient client, string deviceCode, string clientId = "test-device", string? clientSecret = null)
    {
        var form = Form(("grant_type", DeviceGrantType), ("client_id", clientId), ("device_code", deviceCode));
        if (clientSecret is not null)
        {
            form["client_secret"] = clientSecret;
        }

        return PostFormAsync(client, TokenPath, form);
    }

    public static string NewNonce() => "n-" + Guid.NewGuid().ToString("N");

    // /account/session: セッション Cookie の発行・確認・破棄
    public static Task<OauthResponse> SignInAsync(HttpClient client, string username = "alice", string password = "password") =>
        PostFormAsync(client, SessionPath, Form(("username", username), ("password", password)));

    public static Task<OauthResponse> QuerySessionAsync(HttpClient client) => GetAsync(client, SessionPath);

    public static Task<OauthResponse> SignOutAsync(HttpClient client) => SendAsync(client, HttpMethod.Delete, SessionPath);

    // GET /connect/authorize (方式 A) の URL を組み立てる。値が null のパラメーターは送らない。
    public static string BuildAuthorizeUrl(params (string Key, string? Value)[] parameters) =>
        AuthorizePath + "?" + String.Join(
            '&',
            parameters
                .Where(p => p.Value is not null)
                .Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value!)}"));

    // リダイレクト応答の Location からクエリパラメーターを取り出す
    public static Dictionary<string, string> ParseRedirect(string? location)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        if (String.IsNullOrEmpty(location))
        {
            return result;
        }

        var separator = location.IndexOf('?', StringComparison.Ordinal);
        if (separator < 0)
        {
            return result;
        }

        foreach (var pair in location[(separator + 1)..].Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var index = pair.IndexOf('=', StringComparison.Ordinal);
            if (index > 0)
            {
                result[Uri.UnescapeDataString(pair[..index])] = Uri.UnescapeDataString(pair[(index + 1)..]);
            }
        }

        return result;
    }

    public static (string Verifier, string Challenge) CreatePkce()
    {
        var verifier = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
        var challenge = Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        return (verifier, challenge);
    }

    public static string BasicAuthorization(string clientId, string clientSecret) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Uri.EscapeDataString(clientId)}:{Uri.EscapeDataString(clientSecret)}"));

    // RFC 7523 のクライアントアサーション。既定では 60 秒の寿命で jti を毎回新しくする
    public static string CreateClientAssertion(
        string clientId, string audience, string privateJwkJson = DevPrivateJwk, string? jti = null, TimeSpan? lifetime = null)
    {
        var key = new JsonWebKey(privateJwkJson);
        var now = DateTime.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = clientId,
            Audience = audience,
            IssuedAt = now,
            NotBefore = now,
            Expires = now.Add(lifetime ?? TimeSpan.FromSeconds(60)),
            Claims = new Dictionary<string, object>
            {
                ["sub"] = clientId,
                ["jti"] = jti ?? Guid.NewGuid().ToString("N")
            },
            SigningCredentials = new SigningCredentials(key, key.Alg ?? SecurityAlgorithms.EcdsaSha256)
        };
        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        return handler.CreateToken(descriptor);
    }

    public static Task<OauthResponse> ClientCredentialsWithAssertionAsync(HttpClient client, string assertion, string scope = "api.read", string assertionType = JwtBearerAssertionType) =>
        PostFormAsync(client, TokenPath, Form(
            ("grant_type", "client_credentials"),
            ("scope", scope),
            ("client_assertion_type", assertionType),
            ("client_assertion", assertion)));

    public static JsonElement JwtHeader(string token) => DecodeJwtPart(token, 0);

    public static JsonElement JwtPayload(string token) => DecodeJwtPart(token, 1);

    // 署名の末尾 1 文字を変えて改ざんされたトークンを作る
    public static string Tamper(string token)
    {
        var last = token[^1];
        return token[..^1] + (last == 'A' ? 'B' : 'A');
    }

    private static JsonElement DecodeJwtPart(string token, int index)
    {
        var part = token.Split('.')[index];
        using var document = JsonDocument.Parse(Base64Url.DecodeFromChars(part));
        return document.RootElement.Clone();
    }
}

// 応答のステータス・ヘッダー・JSON 本文をまとめて保持する (HttpResponseMessage は読み終えたら破棄する)
internal sealed class OauthResponse
{
    private readonly Dictionary<string, string> headers;

    private OauthResponse(Dictionary<string, string> headers)
    {
        this.headers = headers;
    }

    public HttpStatusCode Status { get; private init; }

    public string Text { get; private init; } = string.Empty;

    // JSON でない場合は ValueKind == Undefined
    public JsonElement Body { get; private init; }

    public string? Error => GetString("error");

    public string? ErrorDescription => GetString("error_description");

    public bool IsJsonObject => Body.ValueKind == JsonValueKind.Object;

    public static async Task<OauthResponse> FromAsync(HttpResponseMessage response)
    {
        var text = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        var body = default(JsonElement);
        if (!String.IsNullOrWhiteSpace(text))
        {
            try
            {
                using var document = JsonDocument.Parse(text);
                body = document.RootElement.Clone();
            }
            catch (JsonException)
            {
                // JSON 以外 (HTML のエラーページなど) はそのまま Text で参照する
            }
        }

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in response.Headers.Concat(response.Content.Headers))
        {
            headers[header.Key] = String.Join(", ", header.Value);
        }

        return new OauthResponse(headers) { Status = response.StatusCode, Text = text, Body = body };
    }

    public string? Header(string name) => headers.TryGetValue(name, out var value) ? value : null;

    public bool HasProperty(string name) => IsJsonObject && Body.TryGetProperty(name, out _);

    public JsonElement Property(string name) => Body.GetProperty(name);

    public string? GetString(string name) =>
        IsJsonObject && Body.TryGetProperty(name, out var value) && (value.ValueKind == JsonValueKind.String) ? value.GetString() : null;

    public int GetInt32(string name) => Body.GetProperty(name).GetInt32();

    public string[] GetStringArray(string name) =>
        Body.GetProperty(name).EnumerateArray().Select(e => e.GetString()!).ToArray();
}
