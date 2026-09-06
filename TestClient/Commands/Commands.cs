namespace TestClient.Commands;

using System.Text.Json;
using System.Text.Json.Serialization;

using Smart.CommandLine.Hosting;

// ---------------------------------------------------------------------------
// token
// ---------------------------------------------------------------------------
[Command("token", "Authenticate and save tokens to a file")]
public sealed class TokenCommand : ICommandHandler
{
    private readonly HttpClient http;

    public TokenCommand(HttpClient http)
    {
        this.http = http;
    }

    [Option<string>("--auth", "-a", Description = "AuthServer base URL")]
    public string AuthServer { get; set; } = ServerUrls.AuthServer;

    [Option<string>("--grant", "-g", Description = "Grant type (client_credentials | authorization_code | password)")]
    public string GrantType { get; set; } = "client_credentials";

    [Option<string>("--client-id", Description = "Client ID")]
    public string ClientId { get; set; } = "test-client";

    [Option<string>("--client-secret", Description = "Client secret")]
    public string ClientSecret { get; set; } = "test-secret";

    [Option<string>("--scope", "-s", Description = "Requested scope")]
    public string Scope { get; set; } = "api.read api.write";

    // authorization_code / password 用 (Phase 2 以降)
    [Option<string>("--username", "-u", Description = "Username (password grant)")]
    public string? Username { get; set; }

    [Option<string>("--password", "-p", Description = "Password (password grant)")]
    public string? Password { get; set; }

    [Option<string>("--resource", Description = "Resource indicator (RFC 8707): audience URI of the target resource server")]
    public string? Resource { get; set; }

    [Option<string>("--token-file", "-f", Description = "Token file path (default: ~/.testclient/tokens.json)")]
    public string? TokenFilePath { get; set; }

    public async ValueTask ExecuteAsync(CommandContext context)
    {
        var authBase = String.IsNullOrEmpty(AuthServer) ? ServerUrls.AuthServer : AuthServer;
        var grant = String.IsNullOrEmpty(GrantType) ? "client_credentials" : GrantType;

        if (grant == "authorization_code")
        {
            await ExecuteAuthorizationCodeAsync(context, authBase);
            return;
        }

        var form = BuildClientCredentialsForm();

        Console.WriteLine($"Requesting token from {authBase.TrimEnd('/')}/connect/token ...");
        Console.WriteLine($"  grant_type : {form["grant_type"]}");
        Console.WriteLine($"  client_id  : {form["client_id"]}");
        Console.WriteLine($"  scope      : {form["scope"]}");

        using var content = new FormUrlEncodedContent(form);
        var response = await http.PostAsync($"{authBase.TrimEnd('/')}/connect/token", content);
        var body = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            ConsoleHelper.WriteError($"Token request failed: {(int)response.StatusCode} {response.ReasonPhrase}");
            ConsoleHelper.WriteError(body);
            context.ExitCode = 1;
            return;
        }

        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;

        var store = new TokenStore
        {
            AccessToken = root.GetProperty("access_token").GetString(),
            TokenType = root.TryGetProperty("token_type", out var tt) ? tt.GetString() : "Bearer",
            ExpiresIn = root.TryGetProperty("expires_in", out var ei) ? ei.GetInt32() : 3600,
            Scope = root.TryGetProperty("scope", out var sc) ? sc.GetString() : Scope,
            RefreshToken = root.TryGetProperty("refresh_token", out var rt) ? rt.GetString() : null,
            IssuedAt = DateTimeOffset.UtcNow
        };

        TokenFile.Save(store, TokenFilePath);

        ConsoleHelper.WriteSuccess("Token obtained successfully.");
        ConsoleHelper.WriteInfo("access_token", ConsoleHelper.Truncate(store.AccessToken!, 60));
        ConsoleHelper.WriteInfo("expires_in  ", $"{store.ExpiresIn}s (expires at {store.ExpiresAt.ToLocalTime():HH:mm:ss})");
        ConsoleHelper.WriteInfo("scope       ", store.Scope ?? string.Empty);
        ConsoleHelper.WriteInfo("saved to    ", TokenFilePath ?? TokenFile.DefaultPath);
        if (store.RefreshToken is not null)
        {
            ConsoleHelper.WriteInfo("refresh_tkn ", ConsoleHelper.Truncate(store.RefreshToken, 40));
        }
    }

    private async Task ExecuteAuthorizationCodeAsync(CommandContext context, string authBase)
    {
        var clientId = String.IsNullOrEmpty(ClientId) ? "test-webapp" : ClientId;
        var clientSecret = String.IsNullOrEmpty(ClientSecret) ? "webapp-secret" : ClientSecret;
        var scope = String.IsNullOrEmpty(Scope) ? "openid profile email api.read" : Scope;
        var username = Username;
        var password = Password;

        if (String.IsNullOrEmpty(username) || String.IsNullOrEmpty(password))
        {
            ConsoleHelper.WriteError("--username and --password are required for authorization_code grant.");
            context.ExitCode = 1;
            return;
        }

        // PKCE
        var codeVerifier = GeneratePkceVerifier();
        var codeChallenge = ComputeS256Challenge(codeVerifier);
        var state = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        Console.WriteLine($"Requesting authorization code from {authBase.TrimEnd('/')}/connect/authorize ...");
        Console.WriteLine($"  client_id : {clientId}");
        Console.WriteLine($"  scope     : {scope}");
        Console.WriteLine($"  username  : {username}");

        using var authorizeContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = clientId,
            ["redirect_uri"] = "http://localhost:5173/callback",
            ["scope"] = scope,
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256",
            ["state"] = state,
            ["username"] = username,
            ["password"] = password
        });

        var authorizeResponse = await http.PostAsync($"{authBase.TrimEnd('/')}/connect/authorize", authorizeContent);
        var authorizeBody = await authorizeResponse.Content.ReadAsStringAsync();

        if (!authorizeResponse.IsSuccessStatusCode)
        {
            ConsoleHelper.WriteError($"Authorization failed: {(int)authorizeResponse.StatusCode} {authorizeResponse.ReasonPhrase}");
            ConsoleHelper.WriteError(authorizeBody);
            context.ExitCode = 1;
            return;
        }

        using var authorizeDoc = JsonDocument.Parse(authorizeBody);

        // state 検証: 送信した値と一致しない応答は、この要求に対するものではないとみなして中断する
        var returnedState = authorizeDoc.RootElement.TryGetProperty("state", out var st) ? st.GetString() : null;
        if (!String.Equals(returnedState, state, StringComparison.Ordinal))
        {
            ConsoleHelper.WriteError("state mismatch: the authorization response does not belong to this request.");
            context.ExitCode = 1;
            return;
        }

        var code = authorizeDoc.RootElement.GetProperty("code").GetString();
        if (String.IsNullOrEmpty(code))
        {
            ConsoleHelper.WriteError("Authorization code not found in response.");
            context.ExitCode = 1;
            return;
        }

        Console.WriteLine($"  code      : {ConsoleHelper.Truncate(code, 40)}");

        // トークン交換
        Console.WriteLine($"Exchanging code for tokens at {authBase.TrimEnd('/')}/connect/token ...");

        var tokenForm = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = "http://localhost:5173/callback",
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret,
            ["code_verifier"] = codeVerifier
        };
        if (!String.IsNullOrEmpty(Resource))
        {
            tokenForm["resource"] = Resource;
        }

        using var tokenContent = new FormUrlEncodedContent(tokenForm);

        var tokenResponse = await http.PostAsync($"{authBase.TrimEnd('/')}/connect/token", tokenContent);
        var tokenBody = await tokenResponse.Content.ReadAsStringAsync();

        if (!tokenResponse.IsSuccessStatusCode)
        {
            ConsoleHelper.WriteError($"Token exchange failed: {(int)tokenResponse.StatusCode} {tokenResponse.ReasonPhrase}");
            ConsoleHelper.WriteError(tokenBody);
            context.ExitCode = 1;
            return;
        }

        using var tokenDoc = JsonDocument.Parse(tokenBody);
        var tokenRoot = tokenDoc.RootElement;

        var store = new TokenStore
        {
            AccessToken = tokenRoot.GetProperty("access_token").GetString(),
            TokenType = tokenRoot.TryGetProperty("token_type", out var tt) ? tt.GetString() : "Bearer",
            ExpiresIn = tokenRoot.TryGetProperty("expires_in", out var ei) ? ei.GetInt32() : 3600,
            Scope = tokenRoot.TryGetProperty("scope", out var sc) ? sc.GetString() : scope,
            RefreshToken = tokenRoot.TryGetProperty("refresh_token", out var rt) ? rt.GetString() : null,
            IdToken = tokenRoot.TryGetProperty("id_token", out var it) ? it.GetString() : null,
            IssuedAt = DateTimeOffset.UtcNow
        };

        TokenFile.Save(store, TokenFilePath);

        ConsoleHelper.WriteSuccess("Token obtained successfully (authorization_code).");
        ConsoleHelper.WriteInfo("access_token", ConsoleHelper.Truncate(store.AccessToken!, 60));
        ConsoleHelper.WriteInfo("expires_in  ", $"{store.ExpiresIn}s (expires at {store.ExpiresAt.ToLocalTime():HH:mm:ss})");
        ConsoleHelper.WriteInfo("scope       ", store.Scope ?? string.Empty);
        ConsoleHelper.WriteInfo("saved to    ", TokenFilePath ?? TokenFile.DefaultPath);
        if (store.RefreshToken is not null)
        {
            ConsoleHelper.WriteInfo("refresh_tkn ", ConsoleHelper.Truncate(store.RefreshToken, 40));
        }
        if (store.IdToken is not null)
        {
            ConsoleHelper.WriteInfo("id_token    ", ConsoleHelper.Truncate(store.IdToken, 60));
            ConsoleHelper.PrintJwtClaims(store.IdToken);
        }
    }

    private static string GeneratePkceVerifier()
    {
        var bytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static string ComputeS256Challenge(string verifier)
    {
        var bytes = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(verifier));
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private Dictionary<string, string> BuildClientCredentialsForm()
    {
        var clientId = String.IsNullOrEmpty(ClientId) ? "test-client" : ClientId;
        var clientSecret = String.IsNullOrEmpty(ClientSecret) ? "test-secret" : ClientSecret;
        var scope = String.IsNullOrEmpty(Scope) ? "api.read api.write" : Scope;

        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret,
            ["scope"] = scope
        };
        if (!String.IsNullOrEmpty(Resource))
        {
            form["resource"] = Resource;
        }

        return form;
    }
}

// ---------------------------------------------------------------------------
// api
// ---------------------------------------------------------------------------
[Command("api", "Call a protected API endpoint using the saved token")]
public sealed class ApiCommand : ICommandHandler
{
    private readonly HttpClient http;

    public ApiCommand(HttpClient http)
    {
        this.http = http;
    }

    [Option<string>("--resource", "-r", Description = "ResourceServer base URL")]
    public string ResourceServer { get; set; } = ServerUrls.ResourceServer;

    [Option<string>("--path", Description = "API path (default: /api/protected)")]
    public string Path { get; set; } = "/api/protected";

    [Option<string>("--method", "-m", Description = "HTTP method (GET|POST|PUT|DELETE)")]
    public string Method { get; set; } = "GET";

    [Option<string>("--token-file", "-f", Description = "Token file path")]
    public string? TokenFilePath { get; set; }

    public async ValueTask ExecuteAsync(CommandContext context)
    {
        var resourceBase = String.IsNullOrEmpty(ResourceServer) ? ServerUrls.ResourceServer : ResourceServer;
        var apiPath = String.IsNullOrEmpty(Path) ? "/api/protected" : Path;
        var method = String.IsNullOrEmpty(Method) ? "GET" : Method;

        var store = TokenFile.Load(TokenFilePath);
        if (store?.AccessToken is null)
        {
            ConsoleHelper.WriteError("No token found. Run 'token' command first.");
            context.ExitCode = 1;
            return;
        }

        if (store.IsExpired)
        {
            ConsoleHelper.WriteError($"Access token expired at {store.ExpiresAt.ToLocalTime():HH:mm:ss}. Run 'refresh' or 'token' to renew.");
            context.ExitCode = 1;
            return;
        }

        var url = $"{resourceBase.TrimEnd('/')}{apiPath}";
        Console.WriteLine($"{method} {url}");

        using var request = new HttpRequestMessage(
            new HttpMethod(method.ToUpperInvariant()),
            url);
        request.Headers.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", store.AccessToken);

        var response = await http.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();

        Console.WriteLine($"  Status: {(int)response.StatusCode} {response.ReasonPhrase}");
        Console.WriteLine($"  Body  : {body}");

        if (!response.IsSuccessStatusCode)
        {
            context.ExitCode = 2;
        }
    }
}

// ---------------------------------------------------------------------------
// refresh
// ---------------------------------------------------------------------------
[Command("refresh", "Refresh the access token using the saved refresh token")]
public sealed class RefreshCommand : ICommandHandler
{
    private readonly HttpClient http;

    public RefreshCommand(HttpClient http)
    {
        this.http = http;
    }

    [Option<string>("--auth", "-a", Description = "AuthServer base URL")]
    public string AuthServer { get; set; } = ServerUrls.AuthServer;

    [Option<string>("--client-id", Description = "Client ID")]
    public string ClientId { get; set; } = "test-client";

    [Option<string>("--client-secret", Description = "Client secret")]
    public string ClientSecret { get; set; } = "test-secret";

    [Option<string>("--resource", Description = "Resource indicator (RFC 8707): narrow the audience to this resource server URI")]
    public string? Resource { get; set; }

    [Option<string>("--token-file", "-f", Description = "Token file path")]
    public string? TokenFilePath { get; set; }

    public async ValueTask ExecuteAsync(CommandContext context)
    {
        var authBase = String.IsNullOrEmpty(AuthServer) ? ServerUrls.AuthServer : AuthServer;
        var clientId = String.IsNullOrEmpty(ClientId) ? "test-client" : ClientId;
        var clientSecret = String.IsNullOrEmpty(ClientSecret) ? "test-secret" : ClientSecret;

        var store = TokenFile.Load(TokenFilePath);
        if (store?.RefreshToken is null)
        {
            ConsoleHelper.WriteError("No refresh token found. The current grant type may not support refresh. Run 'token' command first.");
            context.ExitCode = 1;
            return;
        }

        Console.WriteLine($"Refreshing token at {authBase.TrimEnd('/')}/connect/token ...");

        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = store.RefreshToken,
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret
        };
        if (!String.IsNullOrEmpty(Resource))
        {
            form["resource"] = Resource;
        }

        using var content = new FormUrlEncodedContent(form);

        var response = await http.PostAsync($"{authBase.TrimEnd('/')}/connect/token", content);
        var body = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            ConsoleHelper.WriteError($"Refresh failed: {(int)response.StatusCode} {response.ReasonPhrase}");
            ConsoleHelper.WriteError(body);
            context.ExitCode = 1;
            return;
        }

        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;

        store.AccessToken = root.GetProperty("access_token").GetString();
        store.TokenType = root.TryGetProperty("token_type", out var tt) ? tt.GetString() : store.TokenType;
        store.ExpiresIn = root.TryGetProperty("expires_in", out var ei) ? ei.GetInt32() : store.ExpiresIn;
        store.Scope = root.TryGetProperty("scope", out var sc) ? sc.GetString() : store.Scope;
        // Rotate refresh token if a new one is issued, otherwise keep the old one
        if (root.TryGetProperty("refresh_token", out var rt))
        {
            store.RefreshToken = rt.GetString();
        }
        store.IssuedAt = DateTimeOffset.UtcNow;

        TokenFile.Save(store, TokenFilePath);

        ConsoleHelper.WriteSuccess("Token refreshed successfully.");
        ConsoleHelper.WriteInfo("access_token", ConsoleHelper.Truncate(store.AccessToken!, 60));
        ConsoleHelper.WriteInfo("expires_in  ", $"{store.ExpiresIn}s (expires at {store.ExpiresAt.ToLocalTime():HH:mm:ss})");
        ConsoleHelper.WriteInfo("saved to    ", TokenFilePath ?? TokenFile.DefaultPath);
    }
}

// ---------------------------------------------------------------------------
// introspect
// ---------------------------------------------------------------------------
[Command("introspect", "Inspect the saved access or refresh token via the introspection endpoint")]
public sealed class IntrospectCommand : ICommandHandler
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private static readonly string[] TokenTypes = ["access", "refresh"];

    private readonly HttpClient http;

    public IntrospectCommand(HttpClient http)
    {
        this.http = http;
    }

    [Option<string>("--auth", "-a", Description = "AuthServer base URL")]
    public string AuthServer { get; set; } = ServerUrls.AuthServer;

    [Option<string>("--client-id", Description = "Client ID")]
    public string ClientId { get; set; } = "test-client";

    [Option<string>("--client-secret", Description = "Client secret")]
    public string ClientSecret { get; set; } = "test-secret";

    [Option<string>("--token-type", "-t", Description = "Token to inspect (access | refresh)")]
    public string TokenType { get; set; } = "access";

    [Option<string>("--token-file", "-f", Description = "Token file path")]
    public string? TokenFilePath { get; set; }

    public async ValueTask ExecuteAsync(CommandContext context)
    {
        var authBase = String.IsNullOrEmpty(AuthServer) ? ServerUrls.AuthServer : AuthServer;
        var clientId = String.IsNullOrEmpty(ClientId) ? "test-client" : ClientId;
        var clientSecret = String.IsNullOrEmpty(ClientSecret) ? "test-secret" : ClientSecret;
        var tokenType = CommandOptionHelper.NormalizeChoice(TokenType, "access", TokenTypes);
        if (tokenType is null)
        {
            ConsoleHelper.WriteError("--token-type must be 'access' or 'refresh'.");
            context.ExitCode = 1;
            return;
        }

        var store = TokenFile.Load(TokenFilePath);
        var token = tokenType == "refresh" ? store?.RefreshToken : store?.AccessToken;
        if (token is null)
        {
            ConsoleHelper.WriteError($"No {tokenType} token found. Run 'token' command first.");
            context.ExitCode = 1;
            return;
        }

        Console.WriteLine($"Introspecting {tokenType} token at {authBase.TrimEnd('/')}/connect/introspect ...");

        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = token,
            ["token_type_hint"] = tokenType == "refresh" ? "refresh_token" : "access_token",
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret
        });

        var response = await http.PostAsync($"{authBase.TrimEnd('/')}/connect/introspect", content);
        var body = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            ConsoleHelper.WriteError($"Introspect failed: {(int)response.StatusCode} {response.ReasonPhrase}");
            ConsoleHelper.WriteError(body);
            context.ExitCode = 1;
            return;
        }

        using var doc = JsonDocument.Parse(body);
        var active = doc.RootElement.TryGetProperty("active", out var a) && a.GetBoolean();
        if (active)
        {
            ConsoleHelper.WriteSuccess("Token is active.");
        }
        else
        {
            ConsoleHelper.WriteError("Token is NOT active (revoked, expired, or unknown).");
        }

        Console.WriteLine(JsonSerializer.Serialize(doc.RootElement, JsonOptions));
    }
}

// ---------------------------------------------------------------------------
// revoke
// ---------------------------------------------------------------------------
[Command("revoke", "Revoke the saved tokens via the revocation endpoint")]
public sealed class RevokeCommand : ICommandHandler
{
    private static readonly string[] TokenTypes = ["all", "access", "refresh"];

    private readonly HttpClient http;

    public RevokeCommand(HttpClient http)
    {
        this.http = http;
    }

    [Option<string>("--auth", "-a", Description = "AuthServer base URL")]
    public string AuthServer { get; set; } = ServerUrls.AuthServer;

    [Option<string>("--client-id", Description = "Client ID")]
    public string ClientId { get; set; } = "test-client";

    [Option<string>("--client-secret", Description = "Client secret")]
    public string ClientSecret { get; set; } = "test-secret";

    [Option<string>("--token-type", "-t", Description = "Token to revoke (all | access | refresh)")]
    public string TokenType { get; set; } = "all";

    [Option<string>("--token-file", "-f", Description = "Token file path")]
    public string? TokenFilePath { get; set; }

    public async ValueTask ExecuteAsync(CommandContext context)
    {
        var authBase = String.IsNullOrEmpty(AuthServer) ? ServerUrls.AuthServer : AuthServer;
        var clientId = String.IsNullOrEmpty(ClientId) ? "test-client" : ClientId;
        var clientSecret = String.IsNullOrEmpty(ClientSecret) ? "test-secret" : ClientSecret;
        var tokenType = CommandOptionHelper.NormalizeChoice(TokenType, "all", TokenTypes);
        if (tokenType is null)
        {
            ConsoleHelper.WriteError("--token-type must be 'all', 'access', or 'refresh'.");
            context.ExitCode = 1;
            return;
        }

        var store = TokenFile.Load(TokenFilePath);
        if ((store is null) || ((store.AccessToken is null) && (store.RefreshToken is null)))
        {
            ConsoleHelper.WriteError("No token found. Run 'token' command first.");
            context.ExitCode = 1;
            return;
        }

        var url = $"{authBase.TrimEnd('/')}/connect/revoke";
        Console.WriteLine($"Revoking token(s) at {url} ...");

        // リソースサーバーはアクセストークンの失効を参照しない (方式 3) ため、セッションを終わらせる意味では
        // リフレッシュトークンの失効が本質。既定では両方を失効させる。
        if ((tokenType is "all" or "refresh") && (store.RefreshToken is not null))
        {
            if (!await RevokeAsync(url, store.RefreshToken, "refresh_token", clientId, clientSecret, context))
            {
                return;
            }

            store.RefreshToken = null;
            ConsoleHelper.WriteInfo("refresh_token", "revoked");
        }

        if ((tokenType is "all" or "access") && (store.AccessToken is not null))
        {
            if (!await RevokeAsync(url, store.AccessToken, "access_token", clientId, clientSecret, context))
            {
                return;
            }

            store.AccessToken = null;
            ConsoleHelper.WriteInfo("access_token ", "revoked (resource servers keep accepting it until it expires)");
        }

        TokenFile.Save(store, TokenFilePath);
        ConsoleHelper.WriteSuccess("Revocation completed and tokens cleared from file.");
    }

    private async Task<bool> RevokeAsync(string url, string token, string hint, string clientId, string clientSecret, CommandContext context)
    {
        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = token,
            ["token_type_hint"] = hint,
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret
        });

        var response = await http.PostAsync(url, content);
        if (response.IsSuccessStatusCode)
        {
            return true;
        }

        var body = await response.Content.ReadAsStringAsync();
        ConsoleHelper.WriteError($"Revoke ({hint}) failed: {(int)response.StatusCode} {response.ReasonPhrase}");
        ConsoleHelper.WriteError(body);
        context.ExitCode = 1;
        return false;
    }
}

// ---------------------------------------------------------------------------
// device
// ---------------------------------------------------------------------------
[Command("device", "Obtain tokens with the Device Authorization Grant (RFC 8628)")]
public sealed class DeviceCommand : ICommandHandler
{
    private const string GrantType = "urn:ietf:params:oauth:grant-type:device_code";

    private readonly HttpClient http;

    public DeviceCommand(HttpClient http)
    {
        this.http = http;
    }

    [Option<string>("--auth", "-a", Description = "AuthServer base URL")]
    public string AuthServer { get; set; } = ServerUrls.AuthServer;

    [Option<string>("--client-id", Description = "Client ID (default: test-device, a public client)")]
    public string ClientId { get; set; } = "test-device";

    [Option<string>("--client-secret", Description = "Client secret (omit for public clients)")]
    public string? ClientSecret { get; set; }

    [Option<string>("--scope", "-s", Description = "Requested scope")]
    public string Scope { get; set; } = "openid profile email api.read";

    [Option<string>("--token-file", "-f", Description = "Token file path")]
    public string? TokenFilePath { get; set; }

    public async ValueTask ExecuteAsync(CommandContext context)
    {
        var authBase = (String.IsNullOrEmpty(AuthServer) ? ServerUrls.AuthServer : AuthServer).TrimEnd('/');
        var clientId = String.IsNullOrEmpty(ClientId) ? "test-device" : ClientId;
        var scope = String.IsNullOrEmpty(Scope) ? "openid profile email api.read" : Scope;

        // 1. デバイス認可要求
        var authorizeForm = new Dictionary<string, string> { ["client_id"] = clientId, ["scope"] = scope };
        if (!String.IsNullOrEmpty(ClientSecret))
        {
            authorizeForm["client_secret"] = ClientSecret;
        }

        Console.WriteLine($"Requesting device authorization from {authBase}/connect/device/authorize ...");
        using var authorizeContent = new FormUrlEncodedContent(authorizeForm);
        var authorizeResponse = await http.PostAsync($"{authBase}/connect/device/authorize", authorizeContent);
        var authorizeBody = await authorizeResponse.Content.ReadAsStringAsync();
        if (!authorizeResponse.IsSuccessStatusCode)
        {
            ConsoleHelper.WriteError($"Device authorization failed: {(int)authorizeResponse.StatusCode} {authorizeResponse.ReasonPhrase}");
            ConsoleHelper.WriteError(authorizeBody);
            context.ExitCode = 1;
            return;
        }

        string deviceCode;
        int expiresIn;
        int interval;
        using (var doc = JsonDocument.Parse(authorizeBody))
        {
            var root = doc.RootElement;
            deviceCode = root.GetProperty("device_code").GetString() ?? string.Empty;
            expiresIn = root.TryGetProperty("expires_in", out var e) ? e.GetInt32() : 600;
            interval = root.TryGetProperty("interval", out var i) ? i.GetInt32() : 5;

            Console.WriteLine();
            ConsoleHelper.WriteSuccess("Open the verification page in a browser and enter the code:");
            ConsoleHelper.WriteInfo("user_code   ", root.GetProperty("user_code").GetString() ?? string.Empty);
            ConsoleHelper.WriteInfo("url         ", root.TryGetProperty("verification_uri_complete", out var vc) ? vc.GetString() ?? string.Empty : root.GetProperty("verification_uri").GetString() ?? string.Empty);
            ConsoleHelper.WriteInfo("expires_in  ", $"{expiresIn}s");
            Console.WriteLine();
        }

        // 2. 承認されるまでトークンエンドポイントをポーリング (RFC 8628 §3.4 / §3.5)
        var deadline = DateTimeOffset.UtcNow.AddSeconds(expiresIn);
        ConsoleHelper.BeginProgress("Waiting for approval");
        while (DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(TimeSpan.FromSeconds(interval));

            var tokenForm = new Dictionary<string, string>
            {
                ["grant_type"] = GrantType,
                ["device_code"] = deviceCode,
                ["client_id"] = clientId
            };
            if (!String.IsNullOrEmpty(ClientSecret))
            {
                tokenForm["client_secret"] = ClientSecret;
            }

            using var tokenContent = new FormUrlEncodedContent(tokenForm);
            var tokenResponse = await http.PostAsync($"{authBase}/connect/token", tokenContent);
            var tokenBody = await tokenResponse.Content.ReadAsStringAsync();

            if (tokenResponse.IsSuccessStatusCode)
            {
                Console.WriteLine();
                SaveTokens(tokenBody, scope);
                return;
            }

            var error = ReadError(tokenBody);
            switch (error)
            {
                case "authorization_pending":
                    Console.Write('.');
                    continue;
                case "slow_down":
                    interval += 5;
                    Console.Write('~');
                    continue;
                case "access_denied":
                    Console.WriteLine();
                    ConsoleHelper.WriteError("The user denied the request.");
                    context.ExitCode = 1;
                    return;
                case "expired_token":
                    Console.WriteLine();
                    ConsoleHelper.WriteError("The device code expired before the user approved it.");
                    context.ExitCode = 1;
                    return;
                default:
                    Console.WriteLine();
                    ConsoleHelper.WriteError($"Token request failed: {(int)tokenResponse.StatusCode} {tokenResponse.ReasonPhrase}");
                    ConsoleHelper.WriteError(tokenBody);
                    context.ExitCode = 1;
                    return;
            }
        }

        Console.WriteLine();
        ConsoleHelper.WriteError("Timed out waiting for approval.");
        context.ExitCode = 1;
    }

    private void SaveTokens(string tokenBody, string requestedScope)
    {
        using var doc = JsonDocument.Parse(tokenBody);
        var root = doc.RootElement;
        var store = new TokenStore
        {
            AccessToken = root.GetProperty("access_token").GetString(),
            TokenType = root.TryGetProperty("token_type", out var tt) ? tt.GetString() : "Bearer",
            ExpiresIn = root.TryGetProperty("expires_in", out var ei) ? ei.GetInt32() : 3600,
            Scope = root.TryGetProperty("scope", out var sc) ? sc.GetString() : requestedScope,
            RefreshToken = root.TryGetProperty("refresh_token", out var rt) ? rt.GetString() : null,
            IdToken = root.TryGetProperty("id_token", out var it) ? it.GetString() : null,
            IssuedAt = DateTimeOffset.UtcNow
        };

        TokenFile.Save(store, TokenFilePath);

        ConsoleHelper.WriteSuccess("Token obtained successfully (device_code).");
        ConsoleHelper.WriteInfo("access_token", ConsoleHelper.Truncate(store.AccessToken!, 60));
        ConsoleHelper.WriteInfo("expires_in  ", $"{store.ExpiresIn}s (expires at {store.ExpiresAt.ToLocalTime():HH:mm:ss})");
        ConsoleHelper.WriteInfo("scope       ", store.Scope ?? string.Empty);
        ConsoleHelper.WriteInfo("saved to    ", TokenFilePath ?? TokenFile.DefaultPath);
        if (store.RefreshToken is not null)
        {
            ConsoleHelper.WriteInfo("refresh_tkn ", ConsoleHelper.Truncate(store.RefreshToken, 40));
        }
        if (store.IdToken is not null)
        {
            ConsoleHelper.WriteInfo("id_token    ", ConsoleHelper.Truncate(store.IdToken, 60));
            ConsoleHelper.PrintJwtClaims(store.IdToken);
        }
    }

    private static string? ReadError(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.TryGetProperty("error", out var e) ? e.GetString() : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

// ---------------------------------------------------------------------------
// userinfo
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// userinfo
// ---------------------------------------------------------------------------
[Command("userinfo", "Fetch user information from the UserInfo endpoint")]
public sealed class UserInfoCommand : ICommandHandler
{
    private readonly HttpClient http;

    public UserInfoCommand(HttpClient http)
    {
        this.http = http;
    }

    [Option<string>("--auth", "-a", Description = "AuthServer base URL")]
    public string AuthServer { get; set; } = ServerUrls.AuthServer;

    [Option<string>("--token-file", "-f", Description = "Token file path")]
    public string? TokenFilePath { get; set; }

    public async ValueTask ExecuteAsync(CommandContext context)
    {
        var authBase = String.IsNullOrEmpty(AuthServer) ? ServerUrls.AuthServer : AuthServer;

        var store = TokenFile.Load(TokenFilePath);
        if (store?.AccessToken is null)
        {
            ConsoleHelper.WriteError("No token found. Run 'token' command first.");
            context.ExitCode = 1;
            return;
        }

        Console.WriteLine($"Fetching UserInfo from {authBase.TrimEnd('/')}/connect/userinfo ...");

        using var request = new HttpRequestMessage(HttpMethod.Get, $"{authBase.TrimEnd('/')}/connect/userinfo");
        request.Headers.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", store.AccessToken);

        var response = await http.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            ConsoleHelper.WriteError($"UserInfo request failed: {(int)response.StatusCode} {response.ReasonPhrase}");
            ConsoleHelper.WriteError(body);
            context.ExitCode = 1;
            return;
        }

        Console.WriteLine(body);
    }
}

// ---------------------------------------------------------------------------
// discovery
// ---------------------------------------------------------------------------
[Command("discovery", "Fetch and display the OpenID Connect discovery document")]
public sealed class DiscoveryCommand : ICommandHandler
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly HttpClient http;

    public DiscoveryCommand(HttpClient http)
    {
        this.http = http;
    }

    [Option<string>("--auth", "-a", Description = "AuthServer base URL")]
    public string AuthServer { get; set; } = ServerUrls.AuthServer;

    public async ValueTask ExecuteAsync(CommandContext context)
    {
        var authBase = String.IsNullOrEmpty(AuthServer) ? ServerUrls.AuthServer : AuthServer;
        var url = $"{authBase.TrimEnd('/')}/.well-known/openid-configuration";
        Console.WriteLine($"Fetching discovery document from {url} ...");

        var response = await http.GetAsync(url);
        var body = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            ConsoleHelper.WriteError($"Discovery request failed: {(int)response.StatusCode}");
            context.ExitCode = 1;
            return;
        }

        // Pretty-print JSON
        using var doc = JsonDocument.Parse(body);
        Console.WriteLine(JsonSerializer.Serialize(doc.RootElement, JsonOptions));
    }
}
