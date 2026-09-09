namespace TestClient.Commands;

using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

using Smart.CommandLine.Hosting;

// ---------------------------------------------------------------------------
// authorize (方式 A: ブラウザリダイレクト方式の Authorization Code Flow)
// ---------------------------------------------------------------------------
// AuthServer にログイン画面がまだないため、ブラウザの代わりにこのコマンドがセッション Cookie を持って
// GET /connect/authorize をたどる。リダイレクト先 (redirect_uri) は --listen でローカル HTTP リスナーが受ける。
[Command("authorize", "Run the redirect-based authorization code flow (方式 A)")]
public sealed partial class AuthorizeCommand : ICommandHandler
{
    private static readonly string[] ResponseModes = ["query", "form_post"];

    private static readonly TimeSpan CallbackTimeout = TimeSpan.FromSeconds(15);

    // コールバックを受けたブラウザーに返す最小のページ
    private static readonly byte[] CallbackPage = "<!DOCTYPE html><html><body>You can close this window.</body></html>"u8.ToArray();

    [Option<string>("--auth", "-a", Description = "AuthServer base URL")]
    public string AuthServer { get; set; } = ServerUrls.AuthServer;

    [Option<string>("--client-id", Description = "Client ID")]
    public string ClientId { get; set; } = "test-webapp";

    [Option<string>("--client-secret", Description = "Client secret")]
    public string ClientSecret { get; set; } = "webapp-secret";

    [Option<string>("--auth-method", Description = "Client authentication for the token request (client_secret_post | client_secret_basic | private_key_jwt | none)")]
    public string AuthMethod { get; set; } = ClientAuthHelper.SecretPost;

    [Option<string>("--client-key", Description = "Private JWK file for private_key_jwt")]
    public string? ClientKeyPath { get; set; }

    [Option<string>("--scope", "-s", Description = "Requested scope")]
    public string Scope { get; set; } = "openid profile email api.read";

    [Option<string>("--username", "-u", Description = "Username used to establish the session")]
    public string Username { get; set; } = "alice";

    [Option<string>("--password", "-p", Description = "Password used to establish the session")]
    public string Password { get; set; } = "password";

    [Option<string>("--redirect-uri", Description = "Redirect URI registered for the client")]
    public string RedirectTarget { get; set; } = "http://localhost:5173/callback";

    [Option<string>("--response-mode", Description = "Authorization response mode (query | form_post)")]
    public string ResponseMode { get; set; } = "query";

    [Option<bool>("--no-listen", Description = "Do not start a local HTTP listener; read the authorization response directly")]
    public bool NoListen { get; set; }

    [Option<string>("--token-file", "-f", Description = "Token file path")]
    public string? TokenFilePath { get; set; }

    public async ValueTask ExecuteAsync(CommandContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var authBase = (String.IsNullOrEmpty(AuthServer) ? ServerUrls.AuthServer : AuthServer).TrimEnd('/');
        var clientId = String.IsNullOrEmpty(ClientId) ? "test-webapp" : ClientId;
        var clientSecret = String.IsNullOrEmpty(ClientSecret) ? "webapp-secret" : ClientSecret;
        var scope = String.IsNullOrEmpty(Scope) ? "openid profile email api.read" : Scope;
        var username = String.IsNullOrEmpty(Username) ? "alice" : Username;
        var password = String.IsNullOrEmpty(Password) ? "password" : Password;
        var redirectTarget = String.IsNullOrEmpty(RedirectTarget) ? "http://localhost:5173/callback" : RedirectTarget;
        var listen = !NoListen;
        var authMethod = ClientAuthHelper.Normalize(AuthMethod);
        if (authMethod is null)
        {
            ConsoleHelper.WriteError(ClientAuthHelper.InvalidMethodMessage);
            context.ExitCode = 1;
            return;
        }

        var responseMode = CommandOptionHelper.NormalizeChoice(ResponseMode, "query", ResponseModes);
        if (responseMode is null)
        {
            ConsoleHelper.WriteError("--response-mode must be 'query' or 'form_post'.");
            context.ExitCode = 1;
            return;
        }

        // ブラウザと同じように Cookie を保持し、リダイレクトは自分で追う
        using var handler = new HttpClientHandler();
        handler.CookieContainer = new CookieContainer();
        handler.AllowAutoRedirect = false;
        handler.CheckCertificateRevocationList = true;
        using var browser = new HttpClient(handler);

        // 1. セッションを確立する (本来はログイン画面。M3 後半で置き換える)
        Console.WriteLine($"Signing in at {authBase}/account/session ...");
        using var signInContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = username,
            ["password"] = password
        });
        var signInResponse = await browser.PostAsync($"{authBase}/account/session", signInContent);
        var signInBody = await signInResponse.Content.ReadAsStringAsync();
        if (!signInResponse.IsSuccessStatusCode)
        {
            ConsoleHelper.WriteError($"Sign-in failed: {(int)signInResponse.StatusCode} {signInResponse.ReasonPhrase}");
            ConsoleHelper.WriteError(signInBody);
            context.ExitCode = 1;
            return;
        }

        using (var signInDoc = JsonDocument.Parse(signInBody))
        {
            ConsoleHelper.WriteInfo("session sub ", signInDoc.RootElement.GetProperty("sub").GetString() ?? String.Empty);
        }

        // 2. 認可要求 (PKCE / state / nonce)
        var codeVerifier = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
        var codeChallenge = Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)));
        var state = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16));
        var nonce = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16));

        var authorizeUrl = BuildAuthorizeUrl(authBase, clientId, redirectTarget, scope, codeChallenge, state, nonce, responseMode);
        Console.WriteLine($"Requesting authorization at {authBase}/connect/authorize ...");
        ConsoleHelper.WriteInfo("client_id   ", clientId);
        ConsoleHelper.WriteInfo("scope       ", scope);
        ConsoleHelper.WriteInfo("response_mode", responseMode);

        var authorizeResponse = await browser.GetAsync(authorizeUrl);
        var parameters = await ReadAuthorizationResponseAsync(browser, authorizeResponse, responseMode, redirectTarget, listen, context);
        authorizeResponse.Dispose();
        if (parameters is null)
        {
            return;
        }

        if (parameters.TryGetValue("error", out var error))
        {
            ConsoleHelper.WriteError($"Authorization failed: {error}");
            if (parameters.TryGetValue("error_description", out var description))
            {
                ConsoleHelper.WriteError(description);
            }

            context.ExitCode = 1;
            return;
        }

        // 3. state 検証 (CSRF 対策。RFC 6749 §10.12)
        if (!parameters.TryGetValue("state", out var returnedState) || !String.Equals(returnedState, state, StringComparison.Ordinal))
        {
            ConsoleHelper.WriteError("state mismatch: the authorization response does not belong to this request.");
            context.ExitCode = 1;
            return;
        }

        if (!parameters.TryGetValue("code", out var code) || String.IsNullOrEmpty(code))
        {
            ConsoleHelper.WriteError("The authorization response did not contain a code.");
            context.ExitCode = 1;
            return;
        }

        ConsoleHelper.WriteInfo("code        ", ConsoleHelper.Truncate(code, 40));

        // 4. トークン交換
        Console.WriteLine($"Exchanging code for tokens at {authBase}/connect/token ...");
        var tokenForm = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = redirectTarget,
            ["code_verifier"] = codeVerifier
        };
        using var tokenRequest = ClientAuthHelper.CreateRequest(
            $"{authBase}/connect/token", tokenForm, clientId, clientSecret, authMethod, ClientKeyPath);
        using var tokenResponse = await browser.SendAsync(tokenRequest);
        var tokenBody = await tokenResponse.Content.ReadAsStringAsync();
        if (!tokenResponse.IsSuccessStatusCode)
        {
            ConsoleHelper.WriteError($"Token exchange failed: {(int)tokenResponse.StatusCode} {tokenResponse.ReasonPhrase}");
            ConsoleHelper.WriteError(tokenBody);
            context.ExitCode = 1;
            return;
        }

        TokenStore store;
        using (var tokenDoc = JsonDocument.Parse(tokenBody))
        {
            var root = tokenDoc.RootElement;
            store = new TokenStore
            {
                AccessToken = root.GetProperty("access_token").GetString(),
                TokenType = root.TryGetProperty("token_type", out var tt) ? tt.GetString() : "Bearer",
                ExpiresIn = root.TryGetProperty("expires_in", out var ei) ? ei.GetInt32() : 3600,
                Scope = root.TryGetProperty("scope", out var sc) ? sc.GetString() : scope,
                RefreshToken = root.TryGetProperty("refresh_token", out var rt) ? rt.GetString() : null,
                IdToken = root.TryGetProperty("id_token", out var it) ? it.GetString() : null,
                IssuedAt = DateTimeOffset.UtcNow
            };
        }

        // 5. nonce 検証 (OIDC Core §3.1.3.7 #11)
        if (store.IdToken is not null)
        {
            if (!String.Equals(ConsoleHelper.ReadJwtClaim(store.IdToken, "nonce"), nonce, StringComparison.Ordinal))
            {
                ConsoleHelper.WriteError("nonce mismatch: the ID token does not belong to this request. Tokens were discarded.");
                context.ExitCode = 1;
                return;
            }
        }

        TokenFile.Save(store, TokenFilePath);

        ConsoleHelper.WriteSuccess("Token obtained successfully (authorization_code / redirect flow).");
        ConsoleHelper.WriteInfo("access_token", ConsoleHelper.Truncate(store.AccessToken!, 60));
        ConsoleHelper.WriteInfo("expires_in  ", $"{store.ExpiresIn}s (expires at {store.ExpiresAt.ToLocalTime():HH:mm:ss})");
        ConsoleHelper.WriteInfo("scope       ", store.Scope ?? String.Empty);
        ConsoleHelper.WriteInfo("saved to    ", TokenFilePath ?? TokenFile.DefaultPath);
        if (store.RefreshToken is not null)
        {
            ConsoleHelper.WriteInfo("refresh_tkn ", ConsoleHelper.Truncate(store.RefreshToken, 40));
        }

        if (store.IdToken is not null)
        {
            ConsoleHelper.WriteInfo("id_token    ", ConsoleHelper.Truncate(store.IdToken, 60));
            ConsoleHelper.WriteInfo("nonce       ", "verified");
            ConsoleHelper.PrintJwtClaims(store.IdToken);
        }
    }

    private static string BuildAuthorizeUrl(
        string authBase, string clientId, string redirectTarget, string scope,
        string codeChallenge, string state, string nonce, string responseMode)
    {
        var query = new List<string>
        {
            "response_type=code",
            "client_id=" + Uri.EscapeDataString(clientId),
            "redirect_uri=" + Uri.EscapeDataString(redirectTarget),
            "scope=" + Uri.EscapeDataString(scope),
            "code_challenge=" + codeChallenge,
            "code_challenge_method=S256",
            "state=" + state,
            "nonce=" + nonce
        };
        if (!String.Equals(responseMode, "query", StringComparison.Ordinal))
        {
            query.Add("response_mode=" + Uri.EscapeDataString(responseMode));
        }

        return $"{authBase}/connect/authorize?{String.Join('&', query)}";
    }

    // 認可応答からパラメーターを取り出す。--listen ならリダイレクト先まで実際に配送して、リスナーが受け取った値を使う。
    private static async Task<Dictionary<string, string>?> ReadAuthorizationResponseAsync(
        HttpClient browser, HttpResponseMessage response, string responseMode, string redirectTarget, bool listen, CommandContext context)
    {
        if (String.Equals(responseMode, "query", StringComparison.Ordinal))
        {
            if (response.StatusCode != HttpStatusCode.Found)
            {
                ConsoleHelper.WriteError($"Expected a redirect but got {(int)response.StatusCode} {response.ReasonPhrase}");
                ConsoleHelper.WriteError(await response.Content.ReadAsStringAsync());
                context.ExitCode = 1;
                return null;
            }

            var location = response.Headers.Location;
            if (location is null)
            {
                ConsoleHelper.WriteError("The redirect response had no Location header.");
                context.ExitCode = 1;
                return null;
            }

            ConsoleHelper.WriteInfo("redirect to ", ConsoleHelper.Truncate(location.AbsoluteUri, 80));
            return listen
                ? await ReceiveOnListenerAsync(browser, new HttpRequestMessage(HttpMethod.Get, location), redirectTarget, context)
                : ParseQuery(location.Query);
        }

        // form_post: 自動送信フォームが返るので、ブラウザの代わりに hidden 値を取り出して POST する
        if (!response.IsSuccessStatusCode)
        {
            ConsoleHelper.WriteError($"Expected an HTML form but got {(int)response.StatusCode} {response.ReasonPhrase}");
            context.ExitCode = 1;
            return null;
        }

        var html = await response.Content.ReadAsStringAsync();
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (Match match in HiddenInputPattern().Matches(html))
        {
            fields[WebUtility.HtmlDecode(match.Groups["name"].Value)] = WebUtility.HtmlDecode(match.Groups["value"].Value);
        }

        if (fields.Count == 0)
        {
            ConsoleHelper.WriteError("The form_post response did not contain any parameters.");
            context.ExitCode = 1;
            return null;
        }

        ConsoleHelper.WriteInfo("form post to", ConsoleHelper.Truncate(redirectTarget, 80));
        if (!listen)
        {
            return fields;
        }

        var request = new HttpRequestMessage(HttpMethod.Post, redirectTarget) { Content = new FormUrlEncodedContent(fields) };
        return await ReceiveOnListenerAsync(browser, request, redirectTarget, context);
    }

    // redirect_uri のオリジンでローカル HTTP リスナーを立て、配送された認可応答を受け取る。
    // ブラウザを使う場合もこのリスナーがそのまま使える (M3 後半)。
    private static async Task<Dictionary<string, string>?> ReceiveOnListenerAsync(
        HttpClient browser, HttpRequestMessage delivery, string redirectTarget, CommandContext context)
    {
        var target = new Uri(redirectTarget);
        var prefix = $"{target.Scheme}://{target.Host}:{target.Port}/";

        using var listener = new HttpListener();
        listener.Prefixes.Add(prefix);
        try
        {
            listener.Start();
        }
        catch (HttpListenerException ex)
        {
            ConsoleHelper.WriteError($"Could not listen on {prefix}: {ex.Message}");
            ConsoleHelper.WriteError("Re-run with --no-listen to read the response directly instead.");
            context.ExitCode = 1;
            delivery.Dispose();
            return null;
        }

        try
        {
            ConsoleHelper.WriteInfo("listening on", prefix);
            var contextTask = listener.GetContextAsync();
            var deliveryTask = browser.SendAsync(delivery);

            HttpListenerContext received;
            try
            {
                received = await contextTask.WaitAsync(CallbackTimeout);
            }
            catch (TimeoutException)
            {
                ConsoleHelper.WriteError($"Timed out waiting for the authorization response on {prefix}");
                context.ExitCode = 1;
                return null;
            }

            Dictionary<string, string> parameters;
            if (received.Request.HttpMethod == "POST")
            {
                using var reader = new StreamReader(received.Request.InputStream, Encoding.UTF8);
                parameters = ParseQuery(await reader.ReadToEndAsync());
            }
            else
            {
                parameters = ParseQuery(received.Request.Url?.Query ?? String.Empty);
            }

            received.Response.ContentType = "text/html; charset=utf-8";
            received.Response.ContentLength64 = CallbackPage.Length;
            await received.Response.OutputStream.WriteAsync(CallbackPage);
            received.Response.Close();

            (await deliveryTask).Dispose();
            ConsoleHelper.WriteInfo("callback    ", $"received {parameters.Count} parameter(s) at {received.Request.Url?.AbsolutePath}");
            return parameters;
        }
        finally
        {
            delivery.Dispose();
        }
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = pair.IndexOf('=', StringComparison.Ordinal);
            if (separator > 0)
            {
                result[Uri.UnescapeDataString(pair[..separator])] = Uri.UnescapeDataString(pair[(separator + 1)..].Replace('+', ' '));
            }
        }

        return result;
    }

    [GeneratedRegex("""<input\s+type="hidden"\s+name="(?<name>[^"]*)"\s+value="(?<value>[^"]*)"\s*/>""")]
    private static partial Regex HiddenInputPattern();
}
