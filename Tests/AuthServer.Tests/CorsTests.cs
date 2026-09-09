namespace AuthServer.Tests;

using System.Net;

using AuthServer.Tests.Infrastructure;

internal sealed class CorsEnabledAuthServerFactory : AuthServerFactory
{
    public const string AllowedOrigin = "https://spa.example";

    protected override IEnumerable<KeyValuePair<string, string?>> Settings =>
    [
        new("Cors:AllowedOrigins:0", AllowedOrigin)
    ];
}

// SEC-10: プロトコルエンドポイントは Cors:AllowedOrigins のオリジンだけに CORS を許可し、Discovery / JWKS は任意オリジンを許可する
public sealed class CorsTests
{
    [Fact]
    public static async Task PreflightFromAnAllowedOriginIsAccepted()
    {
        using var factory = new CorsEnabledAuthServerFactory();
        using var client = factory.CreateClient();
        var response = await Oauth.SendAsync(client, HttpMethod.Options, Oauth.TokenPath, request =>
        {
            request.Headers.Add("Origin", CorsEnabledAuthServerFactory.AllowedOrigin);
            request.Headers.Add("Access-Control-Request-Method", "POST");
            request.Headers.Add("Access-Control-Request-Headers", "authorization, content-type");
        });

        Assert.Equal(HttpStatusCode.NoContent, response.Status);
        Assert.Equal(CorsEnabledAuthServerFactory.AllowedOrigin, response.Header("Access-Control-Allow-Origin"));
        var allowedHeaders = response.Header("Access-Control-Allow-Headers");
        Assert.NotNull(allowedHeaders);
        Assert.Contains("authorization", allowedHeaders, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public static async Task PreflightFromAnUnknownOriginGetsNoCorsHeaders()
    {
        using var factory = new CorsEnabledAuthServerFactory();
        using var client = factory.CreateClient();
        var response = await Oauth.SendAsync(client, HttpMethod.Options, Oauth.TokenPath, request =>
        {
            request.Headers.Add("Origin", "https://evil.example");
            request.Headers.Add("Access-Control-Request-Method", "POST");
        });

        Assert.Null(response.Header("Access-Control-Allow-Origin"));
    }

    [Fact]
    public static async Task ActualRequestFromAnAllowedOriginCarriesTheHeader()
    {
        using var factory = new CorsEnabledAuthServerFactory();
        using var client = factory.CreateClient();
        var response = await Oauth.PostFormAsync(
            client, Oauth.TokenPath,
            Oauth.Form(("grant_type", "client_credentials"), ("client_id", "test-client"), ("client_secret", "test-secret"), ("scope", "api.read")),
            request => request.Headers.Add("Origin", CorsEnabledAuthServerFactory.AllowedOrigin));

        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.Equal(CorsEnabledAuthServerFactory.AllowedOrigin, response.Header("Access-Control-Allow-Origin"));
    }

    [Fact]
    public static async Task WithoutConfiguredOriginsTheApiEmitsNoCorsHeaders()
    {
        using var factory = new AuthServerFactory();
        using var client = factory.CreateClient();
        var response = await Oauth.PostFormAsync(
            client, Oauth.TokenPath,
            Oauth.Form(("grant_type", "client_credentials"), ("client_id", "test-client"), ("client_secret", "test-secret"), ("scope", "api.read")),
            request => request.Headers.Add("Origin", CorsEnabledAuthServerFactory.AllowedOrigin));

        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.Null(response.Header("Access-Control-Allow-Origin"));

        var discovery = await Oauth.GetAsync(client, Oauth.DiscoveryPath, configure: request => request.Headers.Add("Origin", CorsEnabledAuthServerFactory.AllowedOrigin));
        Assert.Equal("*", discovery.Header("Access-Control-Allow-Origin"));
    }
}
