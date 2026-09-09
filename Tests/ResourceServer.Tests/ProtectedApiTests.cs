namespace ResourceServer.Tests;

using System.Net;

using AuthServer.Services;
using AuthServer.Tests.Infrastructure;

using Microsoft.Extensions.DependencyInjection;

// AuthServer が発行したトークンを ResourceServer がオフライン検証で受理・拒否する (発行者・署名・audience・スコープ・方式 3)
public sealed class ProtectedApiTests : IClassFixture<ResourceServerFixture>
{
    private const string ProtectedPath = "/api/protected";
    private const string AdminPath = "/api/protected/admin";
    private const string OtherAudience = "https://localhost:5181";

    private readonly ResourceServerFixture fixture;

    public ProtectedApiTests(ResourceServerFixture fixture)
    {
        this.fixture = fixture;
    }

    [Fact]
    public async Task RequestWithoutATokenIsUnauthorized()
    {
        using var api = fixture.Api.CreateClient();
        var response = await Oauth.GetAsync(api, ProtectedPath);

        Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
        Assert.Contains("Bearer", response.Header("WWW-Authenticate"), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ValidAccessTokenIsAccepted()
    {
        using var auth = fixture.Auth.CreateClient();
        using var api = fixture.Api.CreateClient();
        var token = (await Oauth.ClientCredentialsAsync(auth)).GetString("access_token");

        var response = await Oauth.GetAsync(api, ProtectedPath, token);
        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.Equal("test-client", response.GetString("clientId"));
        Assert.Equal("test-client", response.GetString("subject"));
        Assert.Equal("api.read", response.GetString("scope"));
    }

    [Fact]
    public async Task UserTokenFromTheAuthorizationCodeFlowIsAccepted()
    {
        using var auth = fixture.Auth.CreateClient();
        using var api = fixture.Api.CreateClient();
        var tokens = await Oauth.AuthorizeAndExchangeAsync(auth, "openid api.read");

        var response = await Oauth.GetAsync(api, ProtectedPath, tokens.GetString("access_token"));
        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.Equal("user-001", response.GetString("subject"));
        Assert.Equal("test-webapp", response.GetString("clientId"));
    }

    [Fact]
    public async Task ScopeIsEnforcedPerEndpoint()
    {
        using var auth = fixture.Auth.CreateClient();
        using var api = fixture.Api.CreateClient();

        var readOnly = (await Oauth.ClientCredentialsAsync(auth, scope: "api.read")).GetString("access_token");
        Assert.Equal(HttpStatusCode.Forbidden, (await Oauth.GetAsync(api, AdminPath, readOnly)).Status);

        var readWrite = (await Oauth.ClientCredentialsAsync(auth, scope: "api.read api.write")).GetString("access_token");
        Assert.Equal(HttpStatusCode.OK, (await Oauth.GetAsync(api, AdminPath, readWrite)).Status);
    }

    [Fact]
    public async Task TamperedTokenIsRejected()
    {
        using var auth = fixture.Auth.CreateClient();
        using var api = fixture.Api.CreateClient();
        var token = (await Oauth.ClientCredentialsAsync(auth)).GetString("access_token")!;

        var response = await Oauth.GetAsync(api, ProtectedPath, Oauth.Tamper(token));
        Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
    }

    [Fact]
    public async Task IdTokenIsNotAcceptedAsABearerToken()
    {
        using var auth = fixture.Auth.CreateClient();
        using var api = fixture.Api.CreateClient();
        var tokens = await Oauth.AuthorizeAndExchangeAsync(auth, "openid api.read");

        var response = await Oauth.GetAsync(api, ProtectedPath, tokens.GetString("id_token"));
        Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
    }

    [Fact]
    public async Task TokenIssuedForAnotherAudienceIsRejected()
    {
        var resourceServers = fixture.Auth.Services.GetRequiredService<ResourceServerService>();
        if (!await resourceServers.AudienceExistsAsync(OtherAudience))
        {
            await resourceServers.CreateAsync(new AuthServer.Models.ResourceServer
            {
                Name = "Other Resource Server",
                Audience = OtherAudience,
                Description = "created by ProtectedApiTests",
                IsActive = true
            });
        }

        try
        {
            using var auth = fixture.Auth.CreateClient();
            using var api = fixture.Api.CreateClient();

            var forOther = (await Oauth.ClientCredentialsAsync(auth, extra: ("resource", OtherAudience))).GetString("access_token");
            Assert.Equal(HttpStatusCode.Unauthorized, (await Oauth.GetAsync(api, ProtectedPath, forOther)).Status);

            var forThis = (await Oauth.ClientCredentialsAsync(auth, extra: ("resource", Oauth.DefaultAudience))).GetString("access_token");
            Assert.Equal(HttpStatusCode.OK, (await Oauth.GetAsync(api, ProtectedPath, forThis)).Status);
        }
        finally
        {
            // resource を省略したときの既定の audience は「最初の有効なリソースサーバー」なので、他のテストのために元に戻す
            foreach (var server in (await resourceServers.QueryResourceServerListAsync()).Where(s => s.Audience == OtherAudience))
            {
                await resourceServers.DeleteAsync(server.ResourceServerId);
            }
        }
    }

    [Fact]
    public async Task RevokedAccessTokenStaysValidAtTheResourceServerUntilExpiry()
    {
        // 方式 3: ResourceServer は失効リストを参照しない。失効は AuthServer 側 (Introspection / UserInfo) にだけ反映される
        using var auth = fixture.Auth.CreateClient();
        using var api = fixture.Api.CreateClient();
        var token = (await Oauth.ClientCredentialsAsync(auth)).GetString("access_token")!;

        Assert.Equal(HttpStatusCode.OK, (await Oauth.RevokeAsync(auth, token, "access_token", "test-client", "test-secret")).Status);
        Assert.False((await Oauth.IntrospectAsync(auth, token, "access_token", "test-client", "test-secret")).Property("active").GetBoolean());
        Assert.Equal(HttpStatusCode.OK, (await Oauth.GetAsync(api, ProtectedPath, token)).Status);
    }
}
