namespace AuthServer.Endpoints;

using AuthServer.Services;

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
        AuthorizationCodeService codeService)
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

        // ユーザー認証
        var username = form["username"].ToString();
        var password = form["password"].ToString();
        if (String.IsNullOrEmpty(username) || String.IsNullOrEmpty(password))
        {
            return Error("invalid_request", "username and password are required");
        }

        var user = await userService.AuthenticateAsync(username, password);
        if (user is null)
        {
            return Error("access_denied", "Invalid username or password", StatusCodes.Status401Unauthorized);
        }

        // 認可コード発行
        var grantedScope = String.Join(' ', grantedScopes);
        var code = await codeService.IssueAsync(
            clientId, user.UserId, redirectUri, grantedScope,
            codeChallenge, codeChallengeMethod,
            String.IsNullOrEmpty(nonce) ? null : nonce,
            String.IsNullOrEmpty(state) ? null : state);

        return Results.Json(new
        {
            code,
            state = String.IsNullOrEmpty(state) ? null : state
        });
    }

    private static IResult Error(string code, string description, int status = StatusCodes.Status400BadRequest) =>
        Results.Json(new { error = code, error_description = description }, statusCode: status);
}
