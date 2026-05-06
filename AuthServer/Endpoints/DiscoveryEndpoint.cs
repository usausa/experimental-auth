namespace AuthServer.Endpoints;

using AuthServer.Models;

using Microsoft.Extensions.Options;

public static class DiscoveryEndpoint
{
    public static void MapDiscoveryEndpoint(this WebApplication app)
    {
        app.MapGet("/.well-known/openid-configuration", HandleDiscovery)
            .WithTags("Discovery")
            .WithSummary("OpenID Connect Discovery ドキュメントの取得")
            .WithDescription("認証サーバーのメタデータ(トークンエンドポイント URL、サポートするグラントタイプ等)を返します(RFC 8414 / OpenID Connect Discovery 1.0)。")
            .Produces<object>(StatusCodes.Status200OK, "application/json")
            .AllowAnonymous();
    }

    //--------------------------------------------------------------------------------
    // OpenID Connect Discovery エンドポイント
    // GET /.well-known/openid-configuration
    // クライアントが認証サーバーのメタデータ(トークンエンドポイントURL、サポートするグラントタイプ等)を
    // 取得するための標準エンドポイント(RFC 8414 / OpenID Connect Discovery 1.0)。
    //--------------------------------------------------------------------------------

    private static IResult HandleDiscovery(HttpContext context, IOptions<AuthServerOptions> options)
    {
        var issuer = options.Value.Issuer.TrimEnd('/');
        var doc = new
        {
            issuer,
            token_endpoint = $"{issuer}/connect/token",
            jwks_uri = $"{issuer}/.well-known/jwks.json",
            grant_types_supported = new[] { "client_credentials", "authorization_code", "refresh_token" },
            response_types_supported = new[] { "code" },
            token_endpoint_auth_methods_supported = new[] { "client_secret_post", "client_secret_basic" },
            id_token_signing_alg_values_supported = new[] { "RS256" },
            scopes_supported = new[] { "openid", "profile", "email", "api.read", "api.write" },
            code_challenge_methods_supported = new[] { "S256" }
        };
        return Results.Json(doc);
    }
}
