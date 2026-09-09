namespace AuthServer.Tests;

using System.Net;

using AuthServer.Tests.Infrastructure;

// 失効 (RFC 7009) と検査 (RFC 7662)。アクセストークンの失効は AuthServer 自身のエンドポイントで反映される (方式 3)
public sealed class TokenManagementTests : IClassFixture<AuthServerFactory>
{
    private readonly AuthServerFactory factory;

    public TokenManagementTests(AuthServerFactory factory)
    {
        this.factory = factory;
    }

    [Fact]
    public async Task RevokedAccessTokenIsRejectedByAuthServerEndpoints()
    {
        using var client = factory.CreateClient();
        var token = (await Oauth.ClientCredentialsAsync(client)).GetString("access_token")!;

        var before = await Oauth.IntrospectAsync(client, token, "access_token", "test-client", "test-secret");
        Assert.True(before.Property("active").GetBoolean());
        Assert.Equal("test-client", before.GetString("client_id"));
        Assert.Equal("api.read", before.GetString("scope"));
        Assert.Equal(Oauth.Issuer, before.GetString("iss"));

        var userInfoBefore = await Oauth.UserInfoAsync(client, token);
        Assert.Equal(HttpStatusCode.OK, userInfoBefore.Status);
        Assert.Equal("test-client", userInfoBefore.GetString("sub"));

        var revoke = await Oauth.RevokeAsync(client, token, "access_token", "test-client", "test-secret");
        Assert.Equal(HttpStatusCode.OK, revoke.Status);

        var after = await Oauth.IntrospectAsync(client, token, "access_token", "test-client", "test-secret");
        Assert.False(after.Property("active").GetBoolean());

        var userInfoAfter = await Oauth.UserInfoAsync(client, token);
        Assert.Equal(HttpStatusCode.Unauthorized, userInfoAfter.Status);
        Assert.Equal("invalid_token", userInfoAfter.Error);
    }

    [Fact]
    public async Task RevokedRefreshTokenCannotBeUsedAgain()
    {
        using var client = factory.CreateClient();
        var tokens = await Oauth.AuthorizeAndExchangeAsync(client, "openid api.read");
        var refreshToken = tokens.GetString("refresh_token")!;

        var revoke = await Oauth.RevokeAsync(client, refreshToken, "refresh_token");
        Assert.Equal(HttpStatusCode.OK, revoke.Status);

        var introspection = await Oauth.IntrospectAsync(client, refreshToken, "refresh_token");
        Assert.False(introspection.Property("active").GetBoolean());

        var refresh = await Oauth.RefreshAsync(client, refreshToken);
        Assert.Equal(HttpStatusCode.BadRequest, refresh.Status);
        Assert.Equal("invalid_grant", refresh.Error);
    }

    [Fact]
    public async Task RevocationOfUnknownTokenStillReturnsOk()
    {
        using var client = factory.CreateClient();
        var response = await Oauth.RevokeAsync(client, "no-such-token");

        Assert.Equal(HttpStatusCode.OK, response.Status);
    }

    [Fact]
    public async Task OtherClientCannotRevokeTheToken()
    {
        using var client = factory.CreateClient();
        var token = (await Oauth.AuthorizeAndExchangeAsync(client, "openid api.read")).GetString("access_token")!;

        var revoke = await Oauth.RevokeAsync(client, token, "access_token", "test-client", "test-secret");
        Assert.Equal(HttpStatusCode.OK, revoke.Status);

        var introspection = await Oauth.IntrospectAsync(client, token, "access_token");
        Assert.True(introspection.Property("active").GetBoolean());
    }

    [Fact]
    public async Task IntrospectionRejectsUnsupportedHint()
    {
        using var client = factory.CreateClient();
        var response = await Oauth.IntrospectAsync(client, "anything", "saml");

        Assert.Equal(HttpStatusCode.BadRequest, response.Status);
        Assert.Equal("unsupported_token_type", response.Error);
    }

    [Fact]
    public async Task IdTokenIsNotAnActiveTokenForIntrospection()
    {
        using var client = factory.CreateClient();
        var tokens = await Oauth.AuthorizeAndExchangeAsync(client, "openid");

        var response = await Oauth.IntrospectAsync(client, tokens.GetString("id_token")!);
        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.False(response.Property("active").GetBoolean());
    }

    [Fact]
    public async Task IntrospectionRequiresClientAuthentication()
    {
        using var client = factory.CreateClient();
        var response = await Oauth.IntrospectAsync(client, "anything", clientSecret: "wrong");

        Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
        Assert.Equal("invalid_client", response.Error);
    }

    [Fact]
    public async Task UserInfoRequiresABearerToken()
    {
        using var client = factory.CreateClient();
        var missing = await Oauth.GetAsync(client, Oauth.UserInfoPath);
        Assert.Equal(HttpStatusCode.Unauthorized, missing.Status);

        var invalid = await Oauth.UserInfoAsync(client, "not-a-jwt");
        Assert.Equal(HttpStatusCode.Unauthorized, invalid.Status);
        Assert.Equal("invalid_token", invalid.Error);
    }
}
