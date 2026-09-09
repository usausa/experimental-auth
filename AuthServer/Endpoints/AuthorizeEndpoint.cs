namespace AuthServer.Endpoints;

using System.Globalization;
using System.Text.Json;

using AuthServer.Models;
using AuthServer.Security;
using AuthServer.Services;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

// Authorization Endpoint (RFC 6749 §3.1 / §4.1 / RFC 7636 PKCE / OIDC Core §3.1.2)
//
//   GET  /connect/authorize … 方式 A。セッション Cookie で利用者を判断し、redirect_uri へリダイレクトで認可コードを返す
//   POST /connect/authorize … 方式 B。クライアントが資格情報を直送し、認可コードを JSON で受け取る (API 専用)
//
// 方式 A のセッションは /account/session が発行する。ログイン画面は未実装のため、セッションがない要求には
// ログイン画面へ誘導する代わりに login_required を返す (prompt=none と同じ扱い)。
public static class AuthorizeEndpoint
{
    private const int MaxNonceLength = 512;

    public static void MapAuthorizeEndpoint(this WebApplication app)
    {
        app.MapGet("/connect/authorize", HandleAuthorizeGet)
            .WithTags("Authorization")
            .WithSummary("認可要求 (方式 A: ブラウザリダイレクト)")
            .WithDescription("セッション Cookie で利用者を判断し、redirect_uri へ認可コードを返します(RFC 6749 §4.1.2 / RFC 7636 PKCE)。応答は response_mode に従い query か form_post。セッションがない場合は login_required を返します。")
            .Produces(StatusCodes.Status302Found)
            .Produces<string>(StatusCodes.Status200OK, "text/html")
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .RequireCors(Security.CorsExtensions.ApiPolicy)
            .RequireRateLimiting(Security.RateLimitingExtensions.TokenPolicy)
            .AllowAnonymous();

        app.MapPost("/connect/authorize", HandleAuthorizePost)
            .DisableAntiforgery()
            .WithTags("Authorization")
            .WithSummary("認可コードの発行 (方式 B: API 専用)")
            .WithDescription("ユーザー認証情報を受け取り、認可コードを発行します(RFC 6749 §4.1 / RFC 7636 PKCE)。ブラウザリダイレクトではなく JSON で認可コードを返します。")
            .Accepts<IFormCollection>("application/x-www-form-urlencoded")
            .Produces<object>(StatusCodes.Status200OK, "application/json")
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .RequireCors(Security.CorsExtensions.ApiPolicy)
            .RequireRateLimiting(Security.RateLimitingExtensions.AuthenticationPolicy)
            .AllowAnonymous();
    }

    //--------------------------------------------------------------------------------
    // 方式 A: GET /connect/authorize
    // client_id と redirect_uri が確定するまではリダイレクトしてはならない (RFC 6749 §4.1.2.1)。
    // それ以降のエラーは redirect_uri にエラーパラメーターを載せて返す。
    //--------------------------------------------------------------------------------

    private static async ValueTask<IResult> HandleAuthorizeGet(
        HttpContext context,
        ClientService clientService,
        UserService userService,
        AuthorizationCodeService codeService,
        ReplayGuardService replayGuard,
        AuditLogService auditLog,
        IOptions<AuthServerOptions> options)
    {
        var query = context.Request.Query;
        var clientId = query["client_id"].ToString();
        var redirectUri = query["redirect_uri"].ToString();

        // --- リダイレクトしてはいけない段階 ---
        if (String.IsNullOrEmpty(clientId))
        {
            return Error("invalid_request", "client_id is required");
        }

        var client = await clientService.QueryClientAsync(clientId);
        if (client is null)
        {
            return Error("invalid_client", "Unknown client", StatusCodes.Status401Unauthorized);
        }

        if (String.IsNullOrEmpty(redirectUri))
        {
            return Error("invalid_request", "redirect_uri is required");
        }

        if (!IsRegisteredRedirectUri(client, redirectUri))
        {
            return Error("invalid_request", "redirect_uri is not registered for this client");
        }

        // --- ここから先は redirect_uri へエラーを返す ---
        var state = NullIfEmpty(query["state"].ToString());
        var responseMode = query["response_mode"].ToString();
        if (String.IsNullOrEmpty(responseMode))
        {
            responseMode = AuthorizeResponse.Query;
        }
        else if (!AuthorizeResponse.IsSupportedResponseMode(responseMode))
        {
            return AuthorizeResponse.Error(
                redirectUri, AuthorizeResponse.Query, "invalid_request",
                $"response_mode '{responseMode}' is not supported", state);
        }

        if (!client.AllowsGrantType("authorization_code"))
        {
            return Deny("unauthorized_client", "Client is not allowed to use authorization_code grant");
        }

        if (!String.Equals(query["response_type"].ToString(), "code", StringComparison.Ordinal))
        {
            return Deny("unsupported_response_type", "Only 'code' response_type is supported");
        }

        var codeChallenge = query["code_challenge"].ToString();
        var codeChallengeMethod = query["code_challenge_method"].ToString();
        var pkceError = ValidatePkce(codeChallenge, codeChallengeMethod);
        if (pkceError is not null)
        {
            return Deny("invalid_request", pkceError);
        }

        var scopeResult = ResolveScopes(client, query["scope"].ToString());
        if (scopeResult.Error is not null)
        {
            return Deny("invalid_scope", scopeResult.Error);
        }

        var nonce = NullIfEmpty(query["nonce"].ToString());
        var nonceError = ValidateNonce(nonce, scopeResult.IncludesOpenId, options.Value.RequireNonce);
        if (nonceError is not null)
        {
            return Deny("invalid_request", nonceError);
        }

        // prompt (OIDC Core §3.1.2.1)。none は他の値と併用できない
        var prompts = query["prompt"].ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (Array.Exists(prompts, p => p == "none") && (prompts.Length > 1))
        {
            return Deny("invalid_request", "prompt=none must not be combined with other values");
        }

        var ip = context.Connection.RemoteIpAddress?.ToString();

        // セッション確認。ログイン画面が未実装なので、未ログインは prompt の指定によらず login_required を返す
        var session = SessionAuthentication.Resolve(context.User);
        if (session is null)
        {
            await auditLog.RecordAsync(new AuditEntry(
                AuditEvents.Authorize, AuditOutcome.Failure, clientId, null, null, ip, "no active session (login_required)"));
            return Deny("login_required", "No active session. Sign in at /account/session first.");
        }

        var user = await userService.QueryUserAsync(session.UserId);
        if ((user is null) || !user.IsActive)
        {
            await context.SignOutAsync(SessionAuthentication.SchemeName);
            await auditLog.RecordAsync(new AuditEntry(
                AuditEvents.Authorize, AuditOutcome.Failure, clientId, session.UserId, session.Username, ip,
                "session user is missing or inactive"));
            return Deny("login_required", "The signed-in user is no longer active");
        }

        // max_age: 前回認証からの経過が長すぎる場合は再認証が要る (OIDC Core §3.1.2.1)
        if (Int32.TryParse(query["max_age"].ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var maxAge) &&
            (maxAge >= 0) &&
            ((DateTime.UtcNow - session.AuthTime).TotalSeconds > maxAge))
        {
            return Deny("login_required", "Re-authentication is required (max_age exceeded)");
        }

        // 再認証・同意・アカウント選択はいずれも画面が要るため、M3 後半までは対応するエラーを返す
        if (Array.Exists(prompts, p => p == "login"))
        {
            return Deny("login_required", "prompt=login requires the login page (not implemented yet)");
        }

        if (Array.Exists(prompts, p => p == "consent"))
        {
            return Deny("consent_required", "prompt=consent requires the consent page (not implemented yet)");
        }

        if (Array.Exists(prompts, p => p == "select_account"))
        {
            return Deny("account_selection_required", "prompt=select_account is not supported");
        }

        if (!await TryRegisterNonceAsync(replayGuard, auditLog, options.Value, clientId, nonce, session.UserId, session.Username, ip))
        {
            return Deny("invalid_request", "nonce has already been used");
        }

        var code = await codeService.IssueAsync(
            clientId, session.UserId, redirectUri, scopeResult.GrantedScope,
            codeChallenge, codeChallengeMethod, nonce, state, session.AuthTime);

        await auditLog.RecordAsync(new AuditEntry(
            AuditEvents.Authorize, AuditOutcome.Success, clientId, session.UserId, session.Username, ip,
            $"redirect flow; scope={scopeResult.GrantedScope}; response_mode={responseMode}; nonce={(nonce is null ? "no" : "yes")}"));

        return AuthorizeResponse.Code(redirectUri, responseMode, code, state);

        IResult Deny(string error, string description) =>
            AuthorizeResponse.Error(redirectUri, responseMode, error, description, state);
    }

    //--------------------------------------------------------------------------------
    // 方式 B: POST /connect/authorize
    // クライアントがユーザー資格情報と PKCE パラメーターを POST し、認可コードを JSON で受け取る。
    // ブラウザリダイレクトもサーバー側セッションも使わないため、API だけで完結する。
    //--------------------------------------------------------------------------------

    private static async ValueTask<IResult> HandleAuthorizePost(
        HttpContext context,
        ClientService clientService,
        UserService userService,
        AuthorizationCodeService codeService,
        ReplayGuardService replayGuard,
        AuditLogService auditLog,
        IOptions<AuthServerOptions> options)
    {
        if (!context.Request.HasFormContentType)
        {
            return Error("invalid_request", "Form content required");
        }

        var form = await context.Request.ReadFormAsync(context.RequestAborted);

        if (!String.Equals(form["response_type"].ToString(), "code", StringComparison.Ordinal))
        {
            return Error("unsupported_response_type", "Only 'code' response_type is supported");
        }

        var clientId = form["client_id"].ToString();
        if (String.IsNullOrEmpty(clientId))
        {
            return Error("invalid_request", "client_id is required");
        }

        var redirectUri = form["redirect_uri"].ToString();
        if (String.IsNullOrEmpty(redirectUri))
        {
            return Error("invalid_request", "redirect_uri is required");
        }

        var codeChallenge = form["code_challenge"].ToString();
        var codeChallengeMethod = form["code_challenge_method"].ToString();
        var pkceError = ValidatePkce(codeChallenge, codeChallengeMethod);
        if (pkceError is not null)
        {
            return Error("invalid_request", pkceError);
        }

        var nonce = NullIfEmpty(form["nonce"].ToString());
        var state = NullIfEmpty(form["state"].ToString());

        var client = await clientService.QueryClientAsync(clientId);
        if (client is null)
        {
            return Error("invalid_client", "Unknown client", StatusCodes.Status401Unauthorized);
        }

        if (!client.AllowsGrantType("authorization_code"))
        {
            return Error("unauthorized_client", "Client is not allowed to use authorization_code grant");
        }

        if (!IsRegisteredRedirectUri(client, redirectUri))
        {
            return Error("invalid_request", "redirect_uri is not registered for this client");
        }

        var scopeResult = ResolveScopes(client, form["scope"].ToString());
        if (scopeResult.Error is not null)
        {
            return Error("invalid_scope", scopeResult.Error);
        }

        var nonceError = ValidateNonce(nonce, scopeResult.IncludesOpenId, options.Value.RequireNonce);
        if (nonceError is not null)
        {
            return Error("invalid_request", nonceError);
        }

        // ユーザー認証
        var username = form["username"].ToString();
        var password = form["password"].ToString();
        if (String.IsNullOrEmpty(username) || String.IsNullOrEmpty(password))
        {
            return Error("invalid_request", "username and password are required");
        }

        var ip = context.Connection.RemoteIpAddress?.ToString();
        var user = await userService.AuthenticateAsync(username, password);
        if (user is null)
        {
            await auditLog.RecordAsync(new AuditEntry(
                AuditEvents.Authorize, AuditOutcome.Failure, clientId, null, username, ip, "invalid username or password"));
            return Error("access_denied", "Invalid username or password", StatusCodes.Status401Unauthorized);
        }

        if (!await TryRegisterNonceAsync(replayGuard, auditLog, options.Value, clientId, nonce, user.UserId, username, ip))
        {
            return Error("invalid_request", "nonce has already been used");
        }

        // 方式 B は資格情報の検証直後にコードを発行するため、認証時刻は現在時刻と一致する
        var code = await codeService.IssueAsync(
            clientId, user.UserId, redirectUri, scopeResult.GrantedScope,
            codeChallenge, codeChallengeMethod, nonce, state, DateTime.UtcNow);

        await auditLog.RecordAsync(new AuditEntry(
            AuditEvents.Authorize, AuditOutcome.Success, clientId, user.UserId, username, ip,
            $"scope={scopeResult.GrantedScope}; nonce={(nonce is null ? "no" : "yes")}"));

        return Results.Json(new { code, state });
    }

    //--------------------------------------------------------------------------------
    // 方式 A / B で共通の検証
    //--------------------------------------------------------------------------------

    private static bool IsRegisteredRedirectUri(Client client, string redirectUri)
    {
        if (String.IsNullOrEmpty(client.RedirectUris))
        {
            return false;
        }

        string[] allowed;
        try
        {
            allowed = JsonSerializer.Deserialize<string[]>(client.RedirectUris) ?? [];
        }
        catch (JsonException)
        {
            return false;
        }

        // 完全一致のみ (RFC 6749 §3.1.2.3 / SEC-05)
        return Array.Exists(allowed, u => String.Equals(u, redirectUri, StringComparison.Ordinal));
    }

    private static string? ValidatePkce(string codeChallenge, string codeChallengeMethod)
    {
        if (String.IsNullOrEmpty(codeChallenge))
        {
            return "code_challenge is required (PKCE)";
        }

        return String.Equals(codeChallengeMethod, "S256", StringComparison.OrdinalIgnoreCase)
            ? null
            : "code_challenge_method must be S256";
    }

    // 要求スコープをクライアントの登録スコープ内に収める。省略時は登録済みの全スコープ。
    private static ScopeResolution ResolveScopes(Client client, string requested)
    {
        var allowed = client.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (String.IsNullOrEmpty(requested))
        {
            return new ScopeResolution(allowed, null);
        }

        var granted = requested.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        foreach (var scope in granted)
        {
            if (Array.IndexOf(allowed, scope) < 0)
            {
                return new ScopeResolution([], $"Scope '{scope}' is not allowed for this client");
            }
        }

        return new ScopeResolution(granted, null);
    }

    // nonce 検証 (OIDC Core §3.1.2.1 / §3.1.3.7)。openid を含む要求では必須 (RequireNonce)。
    // 形式は空白を含まない印字可能 ASCII 512 文字以内。
    private static string? ValidateNonce(string? nonce, bool includesOpenId, bool requireNonce)
    {
        if (String.IsNullOrEmpty(nonce))
        {
            return includesOpenId && requireNonce
                ? "nonce is required when the openid scope is requested"
                : null;
        }

        return (nonce.Length > MaxNonceLength) || nonce.Any(c => c is <= ' ' or > '~')
            ? $"nonce must be at most {MaxNonceLength} printable ASCII characters without spaces"
            : null;
    }

    // nonce の一回性 (リプレイ検出)。利用者が確定してから記録することで、未認証の要求に nonce を消費させない。
    // 記録期限 = 認可コードの寿命 + ID Token の寿命 (nonce がトークンとして生きている期間)。
    private static async Task<bool> TryRegisterNonceAsync(
        ReplayGuardService replayGuard,
        AuditLogService auditLog,
        AuthServerOptions options,
        string clientId,
        string? nonce,
        string userId,
        string username,
        string? ip)
    {
        if (String.IsNullOrEmpty(nonce))
        {
            return true;
        }

        var expiresAt = DateTime.UtcNow.AddSeconds(options.AuthorizationCodeLifetimeSeconds + options.IdTokenLifetimeSeconds);
        if (await replayGuard.TryRegisterAsync(ReplayGuardService.AuthorizationNonce, clientId + ":" + nonce, clientId, expiresAt))
        {
            return true;
        }

        await auditLog.RecordAsync(new AuditEntry(
            AuditEvents.ReplayDetected, AuditOutcome.Failure, clientId, userId, username, ip, "nonce reused"));
        return false;
    }

    private static string? NullIfEmpty(string value) => String.IsNullOrEmpty(value) ? null : value;

    private static IResult Error(string code, string description, int status = StatusCodes.Status400BadRequest) =>
        Results.Json(new { error = code, error_description = description }, statusCode: status);
}

// スコープ解決の結果。Error が非 null なら Granted は空。
internal sealed record ScopeResolution(string[] Granted, string? Error)
{
    public bool IncludesOpenId => Array.IndexOf(Granted, "openid") >= 0;

    public string GrantedScope => String.Join(' ', Granted);
}
