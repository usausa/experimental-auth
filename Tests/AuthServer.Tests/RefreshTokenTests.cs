namespace AuthServer.Tests;

using System.Net;

using AuthServer.Tests.Infrastructure;

// リフレッシュトークンのローテーション、リプレイ検出 (ファミリー失効)、クライアント束縛
public sealed class RefreshTokenTests : IClassFixture<AuthServerFactory>
{
    private readonly AuthServerFactory factory;

    public RefreshTokenTests(AuthServerFactory factory)
    {
        this.factory = factory;
    }

    [Fact]
    public async Task RefreshRotatesTheTokenAndReplayRevokesTheFamily()
    {
        using var client = factory.CreateClient();
        var tokens = await Oauth.AuthorizeAndExchangeAsync(client, "openid api.read");
        var firstRefreshToken = tokens.GetString("refresh_token")!;

        var refreshed = await Oauth.RefreshAsync(client, firstRefreshToken);
        Assert.Equal(HttpStatusCode.OK, refreshed.Status);
        var secondRefreshToken = refreshed.GetString("refresh_token")!;
        Assert.NotEqual(firstRefreshToken, secondRefreshToken);
        Assert.NotEqual(tokens.GetString("access_token"), refreshed.GetString("access_token"));

        var access = Oauth.JwtPayload(refreshed.GetString("access_token")!);
        Assert.Equal("user-001", access.GetProperty("sub").GetString());
        Assert.Equal("openid api.read", access.GetProperty("scope").GetString());

        // ローテーション済みの旧トークンの再提示はリプレイとみなし、ファミリー全体 (新トークンも) を失効させる
        var replay = await Oauth.RefreshAsync(client, firstRefreshToken);
        Assert.Equal(HttpStatusCode.BadRequest, replay.Status);
        Assert.Equal("invalid_grant", replay.Error);

        var afterReplay = await Oauth.RefreshAsync(client, secondRefreshToken);
        Assert.Equal(HttpStatusCode.BadRequest, afterReplay.Status);
        Assert.Equal("invalid_grant", afterReplay.Error);
    }

    [Fact]
    public async Task RefreshTokenIsBoundToTheIssuingClient()
    {
        using var client = factory.CreateClient();
        var tokens = await Oauth.AuthorizeAndExchangeAsync(client, "openid api.read");
        var refreshToken = tokens.GetString("refresh_token")!;

        // test-device は refresh_token グラントを持つが、このトークンの発行先ではない
        var otherClient = await Oauth.RefreshAsync(client, refreshToken, clientId: "test-device", clientSecret: null);
        Assert.Equal(HttpStatusCode.BadRequest, otherClient.Status);
        Assert.Equal("invalid_grant", otherClient.Error);

        // test-client は refresh_token グラント自体を持たない
        var noGrant = await Oauth.RefreshAsync(client, refreshToken, clientId: "test-client", clientSecret: "test-secret");
        Assert.Equal(HttpStatusCode.BadRequest, noGrant.Status);
        Assert.Equal("unauthorized_client", noGrant.Error);
    }

    [Fact]
    public async Task RefreshTokenIntrospectionReportsTheIdleLifetime()
    {
        using var client = factory.CreateClient();
        var tokens = await Oauth.AuthorizeAndExchangeAsync(client, "openid api.read");

        var introspection = await Oauth.IntrospectAsync(client, tokens.GetString("refresh_token")!, "refresh_token");
        Assert.Equal(HttpStatusCode.OK, introspection.Status);
        Assert.True(introspection.Property("active").GetBoolean());
        Assert.Equal("refresh_token", introspection.GetString("token_type"));
        Assert.Equal("user-001", introspection.GetString("sub"));
        Assert.Equal(604800, introspection.Property("exp").GetInt64() - introspection.Property("iat").GetInt64());
    }

    [Fact]
    public async Task UnknownRefreshTokenIsRejected()
    {
        using var client = factory.CreateClient();
        var response = await Oauth.RefreshAsync(client, "not-a-real-refresh-token");

        Assert.Equal(HttpStatusCode.BadRequest, response.Status);
        Assert.Equal("invalid_grant", response.Error);
    }
}
