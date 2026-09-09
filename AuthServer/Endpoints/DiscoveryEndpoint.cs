namespace AuthServer.Endpoints;

using AuthServer.Models;
using AuthServer.Services;

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
            .RequireCors(AuthServer.Security.CorsExtensions.PublicMetadataPolicy)
            .AllowAnonymous();
    }

    //--------------------------------------------------------------------------------
    // OpenID Connect Discovery エンドポイント
    // GET /.well-known/openid-configuration
    // クライアントが認証サーバーのメタデータ(トークンエンドポイントURL、サポートするグラントタイプ等)を
    // 取得するための標準エンドポイント(RFC 8414 / OpenID Connect Discovery 1.0)。
    //--------------------------------------------------------------------------------

    private static readonly string[] BaseScopes = ["openid", "profile", "email", "api.read", "api.write"];

    private static readonly string[] BaseClaims =
    [
        "sub", "iss", "aud", "exp", "iat", "nbf", "jti", "azp", "nonce", "auth_time", "amr", "at_hash",
        "name", "given_name", "family_name", "preferred_username", "email", "email_verified"
    ];

    private static async Task<IResult> HandleDiscovery(IOptions<AuthServerOptions> options, CustomClaimService customClaimService)
    {
        var issuer = options.Value.Issuer.TrimEnd('/');

        // カスタムクレームの定義に応じて claims_supported / scopes_supported を動的に組み立てる
        var definitions = await customClaimService.QueryDefinitionListAsync();
        var scopesSupported = BaseScopes
            .Concat(definitions.Select(d => d.RequiredScope).OfType<string>().Where(s => s.Length > 0))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        var claimsSupported = BaseClaims
            .Concat(definitions.Select(d => d.ClaimType))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        var doc = new
        {
            issuer,
            authorization_endpoint = $"{issuer}/connect/authorize",
            token_endpoint = $"{issuer}/connect/token",
            userinfo_endpoint = $"{issuer}/connect/userinfo",
            revocation_endpoint = $"{issuer}/connect/revoke",
            introspection_endpoint = $"{issuer}/connect/introspect",
            device_authorization_endpoint = $"{issuer}/connect/device/authorize",
            jwks_uri = $"{issuer}/.well-known/jwks.json",
            grant_types_supported = new[] { "client_credentials", "authorization_code", "refresh_token", DeviceAuthorizationEndpoint.GrantType },
            response_types_supported = new[] { "code" },
            response_modes_supported = AuthorizeResponse.SupportedResponseModes,
            token_endpoint_auth_methods_supported = ClientAuthenticator.SupportedAuthMethods,
            token_endpoint_auth_signing_alg_values_supported = ClientAuthenticator.SupportedAssertionAlgorithms,
            revocation_endpoint_auth_methods_supported = ClientAuthenticator.SupportedAuthMethods,
            introspection_endpoint_auth_methods_supported = ClientAuthenticator.SupportedAuthMethods,
            id_token_signing_alg_values_supported = new[] { "RS256", "ES256" },
            scopes_supported = scopesSupported,
            code_challenge_methods_supported = new[] { "S256" },
            subject_types_supported = new[] { "public" },
            claims_supported = claimsSupported,
            // 省略時の既定値が true のため、未対応であることを明示する
            request_uri_parameter_supported = false
        };
        return Results.Json(doc);
    }
}
