namespace AuthServer.Endpoints;

using AuthServer.Security;
using AuthServer.Services;

// UserInfo Endpoint (OIDC Core 1.0 §5.3)
// GET / POST /connect/userinfo
// アクセストークンに紐づくユーザーのクレームを返す。OIDC Core §5.3.1 は GET と POST の両対応を MUST としており、
// POST では Authorization ヘッダーの代わりにフォームの access_token でもトークンを受け取る。
public static class UserInfoEndpoint
{
    public static void MapUserInfoEndpoint(this WebApplication app)
    {
        app.MapGet("/connect/userinfo", HandleUserInfo)
            .WithTags("UserInfo")
            .WithSummary("ユーザー情報の取得")
            .WithDescription("Bearer アクセストークンを検証し、トークンに紐づくユーザーのクレームを返します(OIDC Core 1.0 §5.3)。失効済みトークンは拒否します。")
            .Produces<object>(StatusCodes.Status200OK, "application/json")
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .RequireCors(AuthServer.Security.CorsExtensions.ApiPolicy)
            .RequireRateLimiting(AuthServer.Security.RateLimitingExtensions.TokenPolicy)
            .RequireNoStore()
            .AllowAnonymous();

        app.MapPost("/connect/userinfo", HandleUserInfo)
            .DisableAntiforgery()
            .WithTags("UserInfo")
            .WithSummary("ユーザー情報の取得 (POST)")
            .WithDescription("OIDC Core 1.0 §5.3.1 が MUST とする POST 版です。Authorization ヘッダーのほか、フォームの access_token でもトークンを受け取ります。")
            .Accepts<IFormCollection>("application/x-www-form-urlencoded")
            .Produces<object>(StatusCodes.Status200OK, "application/json")
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .RequireCors(AuthServer.Security.CorsExtensions.ApiPolicy)
            .RequireRateLimiting(AuthServer.Security.RateLimitingExtensions.TokenPolicy)
            .RequireNoStore()
            .AllowAnonymous();
    }

    //--------------------------------------------------------------------------------
    // UserInfo エンドポイント
    // GET /connect/userinfo
    // Authorization: Bearer <access_token> で呼び出す。
    // アクセストークンの sub クレームを元にユーザー情報を取得し、付与されたスコープに応じたクレームを返す。
    //--------------------------------------------------------------------------------

    private static async ValueTask<IResult> HandleUserInfo(
        HttpContext context,
        TokenService tokenService,
        RevokedTokenService revokedTokenService,
        UserService userService,
        CustomClaimService customClaimService)
    {
        var (resolvedToken, resolveError) = await ResolveAccessTokenAsync(context);
        if (resolveError is not null)
        {
            return resolveError;
        }

        var accessToken = resolvedToken!;

        // JWT 検証 (署名・発行者・有効期限・typ=at+jwt) と失効リストの照合
        var claims = await tokenService.ValidateAccessTokenAsync(accessToken);
        if (claims is null)
        {
            return Unauthorized("Token validation failed");
        }

        if (await revokedTokenService.IsRevokedAsync(claims.Jti))
        {
            return Unauthorized("Token has been revoked");
        }

        if (String.IsNullOrEmpty(claims.Sub))
        {
            return Unauthorized("Token has no sub claim");
        }

        var scopes = claims.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        var user = await userService.QueryUserAsync(claims.Sub);
        if (user is null)
        {
            // client_credentials の場合は sub = clientId なので最小限のクレームを返す
            return Results.Json(new { sub = claims.Sub });
        }

        var response = new Dictionary<string, object?> { ["sub"] = user.UserId };

        // profile スコープ
        if (Array.IndexOf(scopes, "profile") >= 0)
        {
            if (user.Name is not null)
            {
                response["name"] = user.Name;
            }
            if (user.GivenName is not null)
            {
                response["given_name"] = user.GivenName;
            }
            if (user.FamilyName is not null)
            {
                response["family_name"] = user.FamilyName;
            }
            response["preferred_username"] = user.Username;
        }

        // email スコープ
        if (Array.IndexOf(scopes, "email") >= 0)
        {
            if (user.Email is not null)
            {
                response["email"] = user.Email;
            }
            response["email_verified"] = user.EmailVerified;
        }

        // カスタムクレーム (定義の in_userinfo が有効で、required_scope が付与されているもの)
        var customClaims = await customClaimService.ResolveForUserAsync(user.UserId, scopes);
        foreach (var (claimType, value) in customClaims.UserInfo)
        {
            response[claimType] = value;
        }

        return Results.Json(response);
    }

    // アクセストークンの受け取り口は Authorization ヘッダーかフォームの access_token のどちらか一方。
    // 両方で送るのは RFC 6750 §2 が禁じているため invalid_request で拒否する。
    private static async ValueTask<(string? Token, IResult? Error)> ResolveAccessTokenAsync(HttpContext context)
    {
        string? fromHeader = null;
        var authHeader = context.Request.Headers.Authorization.ToString();
        if (!String.IsNullOrEmpty(authHeader))
        {
            if (!authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                return (null, Unauthorized("Bearer token required"));
            }

            fromHeader = authHeader["Bearer ".Length..].Trim();
        }

        string? fromForm = null;
        if (HttpMethods.IsPost(context.Request.Method) && context.Request.HasFormContentType)
        {
            var form = await context.Request.ReadFormAsync(context.RequestAborted);
            fromForm = form["access_token"].ToString();
        }

        if (!String.IsNullOrEmpty(fromHeader) && !String.IsNullOrEmpty(fromForm))
        {
            return (null, BadRequest("invalid_request", "The access token must be sent in only one place"));
        }

        var token = String.IsNullOrEmpty(fromHeader) ? fromForm : fromHeader;
        return String.IsNullOrEmpty(token)
            ? (null, Unauthorized("Bearer token required"))
            : (token, null);
    }

    private static IResult BadRequest(string code, string description) =>
        Results.Json(new { error = code, error_description = description }, statusCode: StatusCodes.Status400BadRequest);

    private static IResult Unauthorized(string description) =>
        Results.Json(
            new { error = "invalid_token", error_description = description },
            statusCode: StatusCodes.Status401Unauthorized);
}
