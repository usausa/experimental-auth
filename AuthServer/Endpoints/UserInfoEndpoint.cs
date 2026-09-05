namespace AuthServer.Endpoints;

using AuthServer.Models;
using AuthServer.Services;

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

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
            .WithDescription("Bearer アクセストークンを検証し、トークンに紐づくユーザーのクレームを返します(OIDC Core 1.0 §5.3)。")
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
        SigningKeyService signingKeyService,
        UserService userService,
        IOptions<AuthServerOptions> options)
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

        // JWT 検証
        var keys = signingKeyService.GetAllActiveKeys();
        var securityKeys = keys.Select(k =>
        {
            using var rsa = System.Security.Cryptography.RSA.Create();
            rsa.ImportFromPem(k.PublicKeyPem);
            return (SecurityKey)new RsaSecurityKey(rsa.ExportParameters(false)) { KeyId = k.Kid };
        }).ToList();

        var handler = new JsonWebTokenHandler();
        var validationParams = new TokenValidationParameters
        {
            ValidIssuer = options.Value.Issuer,
            IssuerSigningKeys = securityKeys,
            #pragma warning disable CA5404
            ValidateAudience = false,
            #pragma warning restore CA5404
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30)
        };

        var result = await handler.ValidateTokenAsync(accessToken, validationParams);
        if (!result.IsValid)
        {
            return Unauthorized("Token validation failed");
        }

        var claimsIdentity = result.ClaimsIdentity;
        var sub = claimsIdentity.FindFirst("sub")?.Value;
        if (String.IsNullOrEmpty(sub))
        {
            return Unauthorized("Token has no sub claim");
        }

        // client_credentials トークンはユーザーを持たない
        var scopeClaim = claimsIdentity.FindFirst("scope")?.Value ?? string.Empty;
        var scopes = scopeClaim.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        var user = await userService.QueryUserAsync(sub);
        if (user is null)
        {
            // client_credentials の場合は sub = clientId なので最小限のクレームを返す
            return Results.Json(new { sub });
        }

        var claims = new Dictionary<string, object?> { ["sub"] = user.UserId };

        // profile スコープ
        if (Array.IndexOf(scopes, "profile") >= 0)
        {
            if (user.Name is not null)
            {
                claims["name"] = user.Name;
            }
            if (user.GivenName is not null)
            {
                claims["given_name"] = user.GivenName;
            }
            if (user.FamilyName is not null)
            {
                claims["family_name"] = user.FamilyName;
            }
            claims["preferred_username"] = user.Username;
        }

        // email スコープ
        if (Array.IndexOf(scopes, "email") >= 0)
        {
            if (user.Email is not null)
            {
                claims["email"] = user.Email;
            }
            claims["email_verified"] = user.EmailVerified;
        }

        return Results.Json(claims);
    }

    private static IResult Unauthorized(string description) =>
        Results.Json(
            new { error = "invalid_token", error_description = description },
            statusCode: StatusCodes.Status401Unauthorized);
}
