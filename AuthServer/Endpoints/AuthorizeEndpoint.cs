namespace AuthServer.Endpoints;

using AuthServer.Models;
using AuthServer.Services;

using Microsoft.Extensions.Options;

// Authorization Endpoint (RFC 6749 §3.1 / RFC 7636 PKCE)
// POST /connect/authorize
// クライアントがユーザー認証情報(username/password)を直接送信し、認可コードを取得するエンドポイント。
// このサーバーは API 専用のため、ブラウザリダイレクトではなく JSON レスポンスで認可コードを返す。
public static class AuthorizeEndpoint
{
    public static void MapAuthorizeEndpoint(this WebApplication app)
    {
        app.MapPost("/connect/authorize", HandleAuthorize)
            .DisableAntiforgery()
            .WithTags("Authorization")
            .WithSummary("認可コードの発行")
            .WithDescription("ユーザー認証情報を受け取り、認可コードを発行します(RFC 6749 §4.1 / RFC 7636 PKCE)。ブラウザリダイレクトではなく JSON で認可コードを返します。")
            .Accepts<IFormCollection>("application/x-www-form-urlencoded")
            .Produces<object>(StatusCodes.Status200OK, "application/json")
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .RequireCors(AuthServer.Security.CorsExtensions.ApiPolicy)
            .RequireRateLimiting(AuthServer.Security.RateLimitingExtensions.AuthenticationPolicy)
            .AllowAnonymous();
    }

    //--------------------------------------------------------------------------------
    // 認可エンドポイント
    // POST /connect/authorize
    // クライアントがユーザー資格情報と PKCE パラメータを POST し、認可コードを JSON で受け取る。
    // 標準の Authorization Code Flow はブラウザリダイレクトを使うが、
    // このサーバーは純粋な API サーバーとして設計されているため、JSON レスポンスを返す。
    //--------------------------------------------------------------------------------

    private static async ValueTask<IResult> HandleAuthorize(
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

        var responseType = form["response_type"].ToString();
        if (!String.Equals(responseType, "code", StringComparison.Ordinal))
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
        if (String.IsNullOrEmpty(codeChallenge))
        {
            return Error("invalid_request", "code_challenge is required (PKCE)");
        }

        if (!String.Equals(codeChallengeMethod, "S256", StringComparison.OrdinalIgnoreCase))
        {
            return Error("invalid_request", "code_challenge_method must be S256");
        }

        var scope = form["scope"].ToString();
        var nonce = form["nonce"].ToString();
        var state = form["state"].ToString();

        // クライアント検証
        var client = await clientService.QueryClientAsync(clientId);
        if (client is null)
        {
            return Error("invalid_client", "Unknown client", StatusCodes.Status401Unauthorized);
        }

        if (!client.AllowsGrantType("authorization_code"))
        {
            return Error("unauthorized_client", "Client is not allowed to use authorization_code grant");
        }

        // redirect_uri 検証
        if (!String.IsNullOrEmpty(client.RedirectUris))
        {
            var allowed = System.Text.Json.JsonSerializer.Deserialize<string[]>(client.RedirectUris) ?? [];
            if (!Array.Exists(allowed, u => String.Equals(u, redirectUri, StringComparison.Ordinal)))
            {
                return Error("invalid_request", "redirect_uri is not registered for this client");
            }
        }

        // スコープ検証
        var allowedScopes = client.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        string[] grantedScopes;
        if (String.IsNullOrEmpty(scope))
        {
            grantedScopes = allowedScopes;
        }
        else
        {
            var requestedScopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            foreach (var s in requestedScopes)
            {
                if (Array.IndexOf(allowedScopes, s) < 0)
                {
                    return Error("invalid_scope", $"Scope '{s}' is not allowed for this client");
                }
            }
            grantedScopes = requestedScopes;
        }

        // nonce 検証 (OIDC Core §3.1.2.1 / §3.1.3.7)。openid を含む要求では必須 (RequireNonce)。
        // 形式は空白を含まない印字可能 ASCII 512 文字以内。再利用の検出はユーザー認証後に行う。
        var includesOpenId = Array.IndexOf(grantedScopes, "openid") >= 0;
        if (String.IsNullOrEmpty(nonce))
        {
            if (includesOpenId && options.Value.RequireNonce)
            {
                return Error("invalid_request", "nonce is required when the openid scope is requested");
            }
        }
        else if ((nonce.Length > 512) || nonce.Any(c => c is <= ' ' or > '~'))
        {
            return Error("invalid_request", "nonce must be at most 512 printable ASCII characters without spaces");
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

        // nonce の一回性 (リプレイ検出)。認証後に記録することで、未認証の要求に nonce を消費させない。
        // 記録期限 = 認可コードの寿命 + ID Token の寿命 (nonce がトークンとして生きている期間)
        if (!String.IsNullOrEmpty(nonce))
        {
            var nonceExpiresAt = DateTime.UtcNow.AddSeconds(
                options.Value.AuthorizationCodeLifetimeSeconds + options.Value.IdTokenLifetimeSeconds);
            if (!await replayGuard.TryRegisterAsync(ReplayGuardService.AuthorizationNonce, clientId + ":" + nonce, clientId, nonceExpiresAt))
            {
                await auditLog.RecordAsync(new AuditEntry(
                    AuditEvents.ReplayDetected, AuditOutcome.Failure, clientId, user.UserId, username, ip, "nonce reused"));
                return Error("invalid_request", "nonce has already been used");
            }
        }

        // 認可コード発行
        var grantedScope = String.Join(' ', grantedScopes);
        var code = await codeService.IssueAsync(
            clientId, user.UserId, redirectUri, grantedScope,
            codeChallenge, codeChallengeMethod,
            String.IsNullOrEmpty(nonce) ? null : nonce,
            String.IsNullOrEmpty(state) ? null : state);

        await auditLog.RecordAsync(new AuditEntry(
            AuditEvents.Authorize, AuditOutcome.Success, clientId, user.UserId, username, ip,
            "scope=" + grantedScope + (String.IsNullOrEmpty(nonce) ? "; nonce=no" : "; nonce=yes")));

        return Results.Json(new
        {
            code,
            state = String.IsNullOrEmpty(state) ? null : state
        });
    }

    private static IResult Error(string code, string description, int status = StatusCodes.Status400BadRequest) =>
        Results.Json(new { error = code, error_description = description }, statusCode: status);
}
