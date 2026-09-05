namespace AuthServer.Endpoints;

using AuthServer.Services;

// UserInfo Endpoint (OIDC Core 1.0 §5.3)
// GET /connect/userinfo
// アクセストークン(Bearer)に紐づくユーザーのクレームを返す。
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
        UserService userService)
    {
        var authHeader = context.Request.Headers.Authorization.ToString();
        if (String.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return Unauthorized("Bearer token required");
        }

        var accessToken = authHeader["Bearer ".Length..].Trim();
        if (String.IsNullOrEmpty(accessToken))
        {
            return Unauthorized("Bearer token is empty");
        }

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

        return Results.Json(response);
    }

    private static IResult Unauthorized(string description) =>
        Results.Json(
            new { error = "invalid_token", error_description = description },
            statusCode: StatusCodes.Status401Unauthorized);
}
