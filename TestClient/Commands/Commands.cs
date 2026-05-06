namespace TestClient.Commands;

using System.Text.Json;

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
    public string AuthServer { get; set; } = "http://localhost:5051";

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

    [Option<string>("--token-file", "-f", Description = "Token file path (default: ~/.testclient/tokens.json)")]
    public string? TokenFilePath { get; set; }

    public async ValueTask ExecuteAsync(CommandContext context)
    {
        var authBase = string.IsNullOrEmpty(AuthServer) ? "http://localhost:5051" : AuthServer;
        var form = BuildForm();
        if (form is null)
        {
            return;
        }

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

    private Dictionary<string, string>? BuildForm()
    {
        var grant = string.IsNullOrEmpty(GrantType) ? "client_credentials" : GrantType;
        var clientId = string.IsNullOrEmpty(ClientId) ? "test-client" : ClientId;
        var clientSecret = string.IsNullOrEmpty(ClientSecret) ? "test-secret" : ClientSecret;
        var scope = string.IsNullOrEmpty(Scope) ? "api.read api.write" : Scope;

        return grant switch
        {
            "client_credentials" => new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = clientId,
                ["client_secret"] = clientSecret,
                ["scope"] = scope
            },
            // TODO : Implement authorization_code and password grants in Phase 2
            _ => UnsupportedGrant(grant)
        };
    }

    private static Dictionary<string, string>? UnsupportedGrant(string grant)
    {
        ConsoleHelper.WriteError($"Grant type '{grant}' is not yet implemented in this client.");
        return null;
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
    public string ResourceServer { get; set; } = "http://localhost:5132";

    [Option<string>("--path", Description = "API path (default: /api/protected)")]
    public string Path { get; set; } = "/api/protected";

    [Option<string>("--method", "-m", Description = "HTTP method (GET|POST|PUT|DELETE)")]
    public string Method { get; set; } = "GET";

    [Option<string>("--token-file", "-f", Description = "Token file path")]
    public string? TokenFilePath { get; set; }

    public async ValueTask ExecuteAsync(CommandContext context)
    {
        var resourceBase = string.IsNullOrEmpty(ResourceServer) ? "http://localhost:5132" : ResourceServer;
        var apiPath = string.IsNullOrEmpty(Path) ? "/api/protected" : Path;
        var method = string.IsNullOrEmpty(Method) ? "GET" : Method;

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
    public string AuthServer { get; set; } = "http://localhost:5051";

    [Option<string>("--client-id", Description = "Client ID")]
    public string ClientId { get; set; } = "test-client";

    [Option<string>("--client-secret", Description = "Client secret")]
    public string ClientSecret { get; set; } = "test-secret";

    [Option<string>("--token-file", "-f", Description = "Token file path")]
    public string? TokenFilePath { get; set; }

    public async ValueTask ExecuteAsync(CommandContext context)
    {
        var authBase = string.IsNullOrEmpty(AuthServer) ? "http://localhost:5051" : AuthServer;
        var clientId = string.IsNullOrEmpty(ClientId) ? "test-client" : ClientId;
        var clientSecret = string.IsNullOrEmpty(ClientSecret) ? "test-secret" : ClientSecret;

        var store = TokenFile.Load(TokenFilePath);
        if (store?.RefreshToken is null)
        {
            ConsoleHelper.WriteError("No refresh token found. The current grant type may not support refresh. Run 'token' command first.");
            context.ExitCode = 1;
            return;
        }

        Console.WriteLine($"Refreshing token at {authBase.TrimEnd('/')}/connect/token ...");

        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = store.RefreshToken,
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret
        });

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
[Command("introspect", "Inspect a token via the introspection endpoint")]
public sealed class IntrospectCommand : ICommandHandler
{
    private readonly HttpClient http;

    public IntrospectCommand(HttpClient http)
    {
        this.http = http;
    }

    [Option<string>("--auth", "-a", Description = "AuthServer base URL")]
    public string AuthServer { get; set; } = "http://localhost:5051";

    [Option<string>("--client-id", Description = "Client ID")]
    public string ClientId { get; set; } = "test-client";

    [Option<string>("--client-secret", Description = "Client secret")]
    public string ClientSecret { get; set; } = "test-secret";

    [Option<string>("--token-file", "-f", Description = "Token file path")]
    public string? TokenFilePath { get; set; }

    public async ValueTask ExecuteAsync(CommandContext context)
    {
        var authBase = string.IsNullOrEmpty(AuthServer) ? "http://localhost:5051" : AuthServer;
        var clientId = string.IsNullOrEmpty(ClientId) ? "test-client" : ClientId;
        var clientSecret = string.IsNullOrEmpty(ClientSecret) ? "test-secret" : ClientSecret;

        var store = TokenFile.Load(TokenFilePath);
        if (store?.AccessToken is null)
        {
            ConsoleHelper.WriteError("No token found. Run 'token' command first.");
            context.ExitCode = 1;
            return;
        }

        Console.WriteLine($"Introspecting token at {authBase.TrimEnd('/')}/connect/introspect ...");

        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = store.AccessToken,
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

        Console.WriteLine(body);
    }
}

// ---------------------------------------------------------------------------
// revoke
// ---------------------------------------------------------------------------
[Command("revoke", "Revoke the saved access token")]
public sealed class RevokeCommand : ICommandHandler
{
    private readonly HttpClient http;

    public RevokeCommand(HttpClient http)
    {
        this.http = http;
    }

    [Option<string>("--auth", "-a", Description = "AuthServer base URL")]
    public string AuthServer { get; set; } = "http://localhost:5051";

    [Option<string>("--client-id", Description = "Client ID")]
    public string ClientId { get; set; } = "test-client";

    [Option<string>("--client-secret", Description = "Client secret")]
    public string ClientSecret { get; set; } = "test-secret";

    [Option<string>("--token-file", "-f", Description = "Token file path")]
    public string? TokenFilePath { get; set; }

    public async ValueTask ExecuteAsync(CommandContext context)
    {
        var authBase = string.IsNullOrEmpty(AuthServer) ? "http://localhost:5051" : AuthServer;
        var clientId = string.IsNullOrEmpty(ClientId) ? "test-client" : ClientId;
        var clientSecret = string.IsNullOrEmpty(ClientSecret) ? "test-secret" : ClientSecret;

        var store = TokenFile.Load(TokenFilePath);
        if (store?.AccessToken is null)
        {
            ConsoleHelper.WriteError("No token found. Run 'token' command first.");
            context.ExitCode = 1;
            return;
        }

        Console.WriteLine($"Revoking token at {authBase.TrimEnd('/')}/connect/revoke ...");

        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = store.AccessToken,
            ["token_type_hint"] = "access_token",
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret
        });

        var response = await http.PostAsync($"{authBase.TrimEnd('/')}/connect/revoke", content);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync();
            ConsoleHelper.WriteError($"Revoke failed: {(int)response.StatusCode} {response.ReasonPhrase}");
            ConsoleHelper.WriteError(body);
            context.ExitCode = 1;
            return;
        }

        store.AccessToken = null;
        TokenFile.Save(store, TokenFilePath);
        ConsoleHelper.WriteSuccess("Token revoked and cleared from file.");
    }
}

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
    public string AuthServer { get; set; } = "http://localhost:5051";

    [Option<string>("--token-file", "-f", Description = "Token file path")]
    public string? TokenFilePath { get; set; }

    public async ValueTask ExecuteAsync(CommandContext context)
    {
        var authBase = string.IsNullOrEmpty(AuthServer) ? "http://localhost:5051" : AuthServer;

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
    private readonly HttpClient http;

    public DiscoveryCommand(HttpClient http)
    {
        this.http = http;
    }

    [Option<string>("--auth", "-a", Description = "AuthServer base URL")]
    public string AuthServer { get; set; } = "http://localhost:5051";

    public async ValueTask ExecuteAsync(CommandContext context)
    {
        var authBase = string.IsNullOrEmpty(AuthServer) ? "http://localhost:5051" : AuthServer;
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
        Console.WriteLine(JsonSerializer.Serialize(doc.RootElement, new JsonSerializerOptions { WriteIndented = true }));
    }
}
