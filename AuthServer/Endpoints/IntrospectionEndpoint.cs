namespace AuthServer.Endpoints;

using AuthServer.Models;
using AuthServer.Services;

using Microsoft.Extensions.Options;

// Token Introspection Endpoint (RFC 7662)
// POST /connect/introspect
// トークンの有効性とメタ情報を返す。認証済みクライアントであれば任意のトークンを検査できる (RFC 7662 §2.1 の許容範囲内の簡略化)。
// 応答は常に 200 で、無効・失効・期限切れ・未知のトークンは { "active": false } になる。
public static class IntrospectionEndpoint
{
    public static void MapIntrospectionEndpoint(this WebApplication app)
    {
        app.MapPost("/connect/introspect", HandleIntrospect)
            .DisableAntiforgery()
            .WithTags("Token")
            .WithSummary("トークンの検査")
            .WithDescription("アクセストークンまたはリフレッシュトークンの有効性とメタ情報を返します(RFC 7662)。無効なトークンは { \"active\": false } になります。")
            .Accepts<IFormCollection>("application/x-www-form-urlencoded")
            .Produces<object>(StatusCodes.Status200OK, "application/json")
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .AllowAnonymous();
    }

    private static async ValueTask<IResult> HandleIntrospect(
        HttpContext context,
        ClientService clientService,
        TokenService tokenService,
        RefreshTokenService refreshTokenService,
        RevokedTokenService revokedTokenService,
        IOptions<AuthServerOptions> options)
    {
        if (!context.Request.HasFormContentType)
        {
            return Error("invalid_request", "Form content required");
        }

        var form = await context.Request.ReadFormAsync(context.RequestAborted);

        var (clientId, clientSecret) = ClientAuthentication.ResolveCredentials(context, form);
        if (String.IsNullOrEmpty(clientId))
        {
            return Error("invalid_client", "client_id is required", StatusCodes.Status401Unauthorized);
        }

        var client = await clientService.QueryClientAsync(clientId);
        if ((client is null) || !ClientService.ValidateSecret(client, clientSecret))
        {
            return Error("invalid_client", "Client authentication failed", StatusCodes.Status401Unauthorized);
        }

        var token = form["token"].ToString();
        if (String.IsNullOrEmpty(token))
        {
            return Error("invalid_request", "token is required");
        }

        var hint = form["token_type_hint"].ToString();
        if (!String.IsNullOrEmpty(hint) && (hint is not ("access_token" or "refresh_token")))
        {
            return Error("unsupported_token_type", $"token_type_hint '{hint}' is not supported");
        }

        // ヒントの種別から先に探し、見つからなければもう一方も探す
        var response = hint == "refresh_token"
            ? await IntrospectRefreshTokenAsync(token, refreshTokenService) ??
              await IntrospectAccessTokenAsync(token, tokenService, revokedTokenService, options.Value.Issuer)
            : await IntrospectAccessTokenAsync(token, tokenService, revokedTokenService, options.Value.Issuer) ??
              await IntrospectRefreshTokenAsync(token, refreshTokenService);

        return Results.Json(response ?? Inactive());
    }

    // アクセストークンとして検証できなければ null (他の種別を試す)。検証できたが失効済みなら inactive を返す。
    private static async Task<Dictionary<string, object?>?> IntrospectAccessTokenAsync(
        string token, TokenService tokenService, RevokedTokenService revokedTokenService, string issuer)
    {
        var claims = await tokenService.ValidateAccessTokenAsync(token);
        if (claims is null)
        {
            return null;
        }

        if (await revokedTokenService.IsRevokedAsync(claims.Jti))
        {
            return Inactive();
        }

        var response = new Dictionary<string, object?>
        {
            ["active"] = true,
            ["token_type"] = "Bearer",
            ["client_id"] = claims.ClientId,
            ["sub"] = claims.Sub,
            ["scope"] = claims.Scope,
            ["aud"] = claims.Audience,
            ["iss"] = issuer,
            ["jti"] = claims.Jti,
            ["iat"] = ToUnixTime(claims.IssuedAt),
            ["nbf"] = ToUnixTime(claims.NotBefore),
            ["exp"] = ToUnixTime(claims.ExpiresAt)
        };

        if (claims.Username is not null)
        {
            response["username"] = claims.Username;
        }

        return response;
    }

    private static async Task<Dictionary<string, object?>?> IntrospectRefreshTokenAsync(string token, RefreshTokenService refreshTokenService)
    {
        var info = await refreshTokenService.IntrospectAsync(token);
        if (info is null)
        {
            return null;
        }

        if (!info.Active)
        {
            return Inactive();
        }

        return new Dictionary<string, object?>
        {
            ["active"] = true,
            ["token_type"] = "refresh_token",
            ["client_id"] = info.ClientId,
            ["sub"] = info.UserId,
            ["scope"] = info.Scopes,
            ["iat"] = ToUnixTime(info.CreatedAt),
            ["exp"] = ToUnixTime(info.ExpiresAt)
        };
    }

    private static Dictionary<string, object?> Inactive() => new() { ["active"] = false };

    private static long ToUnixTime(DateTime value) => new DateTimeOffset(value.ToUniversalTime()).ToUnixTimeSeconds();

    private static IResult Error(string code, string description, int status = StatusCodes.Status400BadRequest) =>
        Results.Json(new { error = code, error_description = description }, statusCode: status);
}
