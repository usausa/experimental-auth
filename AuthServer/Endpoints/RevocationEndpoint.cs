namespace AuthServer.Endpoints;

using AuthServer.Services;

// Token Revocation Endpoint (RFC 7009)
// POST /connect/revoke
// クライアントが自身に発行されたアクセストークン / リフレッシュトークンを失効させる。
// 無効・未知・他クライアントのトークンでも 200 を返し、トークンの存在を漏らさない (RFC 7009 §2.2)。
public static class RevocationEndpoint
{
    public static void MapRevocationEndpoint(this WebApplication app)
    {
        app.MapPost("/connect/revoke", HandleRevoke)
            .DisableAntiforgery()
            .WithTags("Token")
            .WithSummary("トークンの失効")
            .WithDescription("アクセストークンまたはリフレッシュトークンを失効させます(RFC 7009)。トークンが無効・未知の場合も 200 を返します。リソースサーバーはアクセストークンの失効を参照しないため、アクセストークンは有効期限まで受理され続けます。")
            .Accepts<IFormCollection>("application/x-www-form-urlencoded")
            .Produces(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .AllowAnonymous();
    }

    private static async ValueTask<IResult> HandleRevoke(
        HttpContext context,
        ClientService clientService,
        TokenService tokenService,
        RefreshTokenService refreshTokenService,
        RevokedTokenService revokedTokenService,
        ILoggerFactory loggerFactory)
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

        // ヒントの種別から先に探し、見つからなければもう一方も探す (RFC 7009 §2.1)
        var revoked = hint == "refresh_token"
            ? await RevokeRefreshTokenAsync(token, client.ClientId, refreshTokenService) ||
              await RevokeAccessTokenAsync(token, client.ClientId, tokenService, revokedTokenService)
            : await RevokeAccessTokenAsync(token, client.ClientId, tokenService, revokedTokenService) ||
              await RevokeRefreshTokenAsync(token, client.ClientId, refreshTokenService);

        var logger = loggerFactory.CreateLogger("RevocationEndpoint");
        if (logger.IsEnabled(LogLevel.Information))
        {
            logger.LogInformation(
                "Revocation requested by {ClientId}: {Result}", client.ClientId, revoked ? "revoked" : "no matching token");
        }

        return Results.Ok();
    }

    private static async Task<bool> RevokeAccessTokenAsync(string token, string clientId, TokenService tokenService, RevokedTokenService revokedTokenService)
    {
        var claims = await tokenService.ValidateAccessTokenAsync(token);
        if ((claims is null) || !String.Equals(claims.ClientId, clientId, StringComparison.Ordinal))
        {
            return false;
        }

        await revokedTokenService.RevokeAsync(claims.Jti, "access_token", claims.ExpiresAt);
        return true;
    }

    private static Task<bool> RevokeRefreshTokenAsync(string token, string clientId, RefreshTokenService refreshTokenService) =>
        refreshTokenService.RevokeAsync(token, clientId);

    private static IResult Error(string code, string description, int status = StatusCodes.Status400BadRequest) =>
        Results.Json(new { error = code, error_description = description }, statusCode: status);
}
