namespace AuthServer.Tests;

using System.Net;

using AuthServer.Tests.Infrastructure;

public sealed class DiscoveryTests : IClassFixture<AuthServerFactory>
{
    private readonly AuthServerFactory factory;

    public DiscoveryTests(AuthServerFactory factory)
    {
        this.factory = factory;
    }

    [Fact]
    public async Task DiscoveryDocumentAdvertisesEndpointsAndCapabilities()
    {
        using var client = factory.CreateClient();
        var response = await Oauth.GetAsync(client, Oauth.DiscoveryPath);

        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.Equal(Oauth.Issuer, response.GetString("issuer"));
        Assert.Equal(Oauth.Issuer + "/connect/token", response.GetString("token_endpoint"));
        Assert.Equal(Oauth.Issuer + "/connect/authorize", response.GetString("authorization_endpoint"));
        Assert.Equal(Oauth.Issuer + "/connect/device/authorize", response.GetString("device_authorization_endpoint"));
        Assert.Equal(Oauth.Issuer + "/.well-known/jwks.json", response.GetString("jwks_uri"));
        Assert.Contains(Oauth.DeviceGrantType, response.GetStringArray("grant_types_supported"));
        Assert.Contains("private_key_jwt", response.GetStringArray("token_endpoint_auth_methods_supported"));
        Assert.Contains("none", response.GetStringArray("token_endpoint_auth_methods_supported"));
        Assert.Contains("ES256", response.GetStringArray("token_endpoint_auth_signing_alg_values_supported"));
        Assert.Contains("RS256", response.GetStringArray("id_token_signing_alg_values_supported"));
        Assert.Contains("department", response.GetStringArray("claims_supported"));
        Assert.Contains("profile", response.GetStringArray("scopes_supported"));

        var challengeMethods = response.GetStringArray("code_challenge_methods_supported");
        Assert.Single(challengeMethods);
        Assert.Equal("S256", challengeMethods[0]);
        Assert.False(response.Property("request_uri_parameter_supported").GetBoolean());
    }

    [Fact]
    public async Task JwksPublishesSigningKeyWithCacheControl()
    {
        using var client = factory.CreateClient();
        var response = await Oauth.GetAsync(client, Oauth.JwksPath);

        Assert.Equal(HttpStatusCode.OK, response.Status);
        var keys = response.Property("keys").EnumerateArray().ToList();
        Assert.NotEmpty(keys);
        Assert.Equal("sig", keys[0].GetProperty("use").GetString());
        Assert.False(String.IsNullOrEmpty(keys[0].GetProperty("kid").GetString()));
        Assert.False(String.IsNullOrEmpty(keys[0].GetProperty("alg").GetString()));

        var cacheControl = response.Header("Cache-Control");
        Assert.NotNull(cacheControl);
        Assert.Contains("max-age", cacheControl, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AccessTokenIsSignedWithAPublishedKey()
    {
        using var client = factory.CreateClient();
        var token = (await Oauth.ClientCredentialsAsync(client)).GetString("access_token")!;
        var kid = Oauth.JwtHeader(token).GetProperty("kid").GetString();

        var jwks = await Oauth.GetAsync(client, Oauth.JwksPath);
        var kids = jwks.Property("keys").EnumerateArray().Select(k => k.GetProperty("kid").GetString()).ToList();
        Assert.Contains(kid, kids);
    }

    [Fact]
    public async Task PublicMetadataAllowsAnyOrigin()
    {
        using var client = factory.CreateClient();
        var response = await Oauth.GetAsync(client, Oauth.DiscoveryPath, configure: request => request.Headers.Add("Origin", "https://spa.example"));

        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.Equal("*", response.Header("Access-Control-Allow-Origin"));
    }
}
