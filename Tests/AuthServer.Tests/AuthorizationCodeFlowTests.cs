namespace AuthServer.Tests;

using System.Net;
using System.Text.Json;

using AuthServer.Tests.Infrastructure;

// 方式 B (API 専用) の Authorization Code Flow + PKCE、nonce の厳密検証、ID Token / UserInfo のクレーム
public sealed class AuthorizationCodeFlowTests : IClassFixture<AuthServerFactory>
{
    private readonly AuthServerFactory factory;

    public AuthorizationCodeFlowTests(AuthServerFactory factory)
    {
        this.factory = factory;
    }

    [Fact]
    public async Task OpenIdRequestWithoutNonceIsRejected()
    {
        using var client = factory.CreateClient();
        var (_, challenge) = Oauth.CreatePkce();
        var response = await Oauth.AuthorizeAsync(client, "openid profile", null, challenge);

        Assert.Equal(HttpStatusCode.BadRequest, response.Status);
        Assert.Equal("invalid_request", response.Error);
        Assert.Contains("nonce", response.ErrorDescription, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("has space")]
    [InlineData("tab\tcharacter")]
    [InlineData("日本語")]
    public async Task MalformedNonceIsRejected(string nonce)
    {
        using var client = factory.CreateClient();
        var (_, challenge) = Oauth.CreatePkce();
        var response = await Oauth.AuthorizeAsync(client, "openid", nonce, challenge);

        Assert.Equal(HttpStatusCode.BadRequest, response.Status);
        Assert.Equal("invalid_request", response.Error);
    }

    [Fact]
    public async Task OverlongNonceIsRejected()
    {
        using var client = factory.CreateClient();
        var (_, challenge) = Oauth.CreatePkce();
        var response = await Oauth.AuthorizeAsync(client, "openid", new string('a', 513), challenge);

        Assert.Equal(HttpStatusCode.BadRequest, response.Status);
        Assert.Equal("invalid_request", response.Error);
    }

    [Fact]
    public async Task NonceIsOptionalWithoutOpenIdScope()
    {
        using var client = factory.CreateClient();
        var (_, challenge) = Oauth.CreatePkce();
        var response = await Oauth.AuthorizeAsync(client, "api.read", null, challenge);

        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.False(String.IsNullOrEmpty(response.GetString("code")));
    }

    [Fact]
    public async Task CodeExchangeReturnsTokensBoundToTheRequest()
    {
        using var client = factory.CreateClient();
        var (verifier, challenge) = Oauth.CreatePkce();
        var nonce = Oauth.NewNonce();

        var authorize = await Oauth.AuthorizeAsync(client, "openid profile email api.read", nonce, challenge, extra: ("state", "state-123"));
        Assert.Equal(HttpStatusCode.OK, authorize.Status);
        Assert.Equal("state-123", authorize.GetString("state"));

        var tokens = await Oauth.ExchangeCodeAsync(client, authorize.GetString("code")!, verifier);
        Assert.Equal(HttpStatusCode.OK, tokens.Status);
        Assert.Equal(900, tokens.GetInt32("expires_in"));
        Assert.False(String.IsNullOrEmpty(tokens.GetString("refresh_token")));

        var idToken = Oauth.JwtPayload(tokens.GetString("id_token")!);
        Assert.Equal(Oauth.Issuer, idToken.GetProperty("iss").GetString());
        Assert.Equal("test-webapp", idToken.GetProperty("aud").GetString());
        Assert.Equal("user-001", idToken.GetProperty("sub").GetString());
        Assert.Equal(nonce, idToken.GetProperty("nonce").GetString());
        Assert.Equal(JsonValueKind.Number, idToken.GetProperty("auth_time").ValueKind);
        Assert.Contains("pwd", idToken.GetProperty("amr").EnumerateArray().Select(e => e.GetString()));
        Assert.False(String.IsNullOrEmpty(idToken.GetProperty("at_hash").GetString()));
        Assert.Equal("alice@example.com", idToken.GetProperty("email").GetString());
        Assert.Equal(JsonValueKind.True, idToken.GetProperty("email_verified").ValueKind);
        Assert.Equal("Engineering", idToken.GetProperty("department").GetString());

        var accessToken = tokens.GetString("access_token")!;
        Assert.Equal("at+jwt", Oauth.JwtHeader(accessToken).GetProperty("typ").GetString());
        var access = Oauth.JwtPayload(accessToken);
        Assert.Equal("user-001", access.GetProperty("sub").GetString());
        Assert.Equal("alice", access.GetProperty("username").GetString());
        Assert.Equal("test-webapp", access.GetProperty("client_id").GetString());
        Assert.Equal(Oauth.DefaultAudience, access.GetProperty("aud").GetString());
        Assert.False(access.TryGetProperty("department", out _), "department is defined for ID Token / UserInfo only");
    }

    [Fact]
    public async Task ProfileScopeGatesTheCustomClaim()
    {
        using var client = factory.CreateClient();
        var tokens = await Oauth.AuthorizeAndExchangeAsync(client, "openid email");

        var idToken = Oauth.JwtPayload(tokens.GetString("id_token")!);
        Assert.False(idToken.TryGetProperty("department", out _));
        Assert.False(idToken.TryGetProperty("name", out _));

        var userInfo = await Oauth.UserInfoAsync(client, tokens.GetString("access_token")!);
        Assert.Equal(HttpStatusCode.OK, userInfo.Status);
        Assert.Equal("alice@example.com", userInfo.GetString("email"));
        Assert.False(userInfo.HasProperty("department"));
    }

    [Fact]
    public async Task UserInfoReturnsScopedClaims()
    {
        using var client = factory.CreateClient();
        var tokens = await Oauth.AuthorizeAndExchangeAsync(client, "openid profile email api.read");

        var userInfo = await Oauth.UserInfoAsync(client, tokens.GetString("access_token")!);
        Assert.Equal(HttpStatusCode.OK, userInfo.Status);
        Assert.Equal("user-001", userInfo.GetString("sub"));
        Assert.Equal("Alice Tester", userInfo.GetString("name"));
        Assert.Equal("alice", userInfo.GetString("preferred_username"));
        Assert.Equal("alice@example.com", userInfo.GetString("email"));
        Assert.Equal("Engineering", userInfo.GetString("department"));
    }

    [Fact]
    public async Task NonceReuseIsRejected()
    {
        using var client = factory.CreateClient();
        var nonce = Oauth.NewNonce();
        var (_, challenge1) = Oauth.CreatePkce();
        var first = await Oauth.AuthorizeAsync(client, "openid", nonce, challenge1);
        Assert.Equal(HttpStatusCode.OK, first.Status);

        var (_, challenge2) = Oauth.CreatePkce();
        var second = await Oauth.AuthorizeAsync(client, "openid", nonce, challenge2);
        Assert.Equal(HttpStatusCode.BadRequest, second.Status);
        Assert.Equal("invalid_request", second.Error);
        Assert.Contains("already", second.ErrorDescription, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WrongCodeVerifierIsRejected()
    {
        using var client = factory.CreateClient();
        var (_, challenge) = Oauth.CreatePkce();
        var (otherVerifier, _) = Oauth.CreatePkce();
        var authorize = await Oauth.AuthorizeAsync(client, "openid", Oauth.NewNonce(), challenge);

        var tokens = await Oauth.ExchangeCodeAsync(client, authorize.GetString("code")!, otherVerifier);
        Assert.Equal(HttpStatusCode.BadRequest, tokens.Status);
        Assert.Equal("invalid_grant", tokens.Error);
    }

    [Fact]
    public async Task CodeReuseRevokesTheRefreshTokenFamily()
    {
        using var client = factory.CreateClient();
        var (verifier, challenge) = Oauth.CreatePkce();
        var authorize = await Oauth.AuthorizeAsync(client, "openid api.read", Oauth.NewNonce(), challenge);
        var code = authorize.GetString("code")!;

        var tokens = await Oauth.ExchangeCodeAsync(client, code, verifier);
        Assert.Equal(HttpStatusCode.OK, tokens.Status);

        var reuse = await Oauth.ExchangeCodeAsync(client, code, verifier);
        Assert.Equal(HttpStatusCode.BadRequest, reuse.Status);
        Assert.Equal("invalid_grant", reuse.Error);

        var refresh = await Oauth.RefreshAsync(client, tokens.GetString("refresh_token")!);
        Assert.Equal(HttpStatusCode.BadRequest, refresh.Status);
        Assert.Equal("invalid_grant", refresh.Error);
    }

    [Fact]
    public async Task UnregisteredRedirectTargetIsRejected()
    {
        using var client = factory.CreateClient();
        var (_, challenge) = Oauth.CreatePkce();
        var response = await Oauth.AuthorizeAsync(client, "openid", Oauth.NewNonce(), challenge, redirectTarget: "http://evil.example/callback");

        Assert.Equal(HttpStatusCode.BadRequest, response.Status);
        Assert.Equal("invalid_request", response.Error);
    }

    [Fact]
    public async Task InvalidPasswordIsDenied()
    {
        using var client = factory.CreateClient();
        var (_, challenge) = Oauth.CreatePkce();
        var response = await Oauth.AuthorizeAsync(client, "openid", Oauth.NewNonce(), challenge, password: "wrong");

        Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
        Assert.Equal("access_denied", response.Error);
    }

    [Fact]
    public async Task ScopeOutsideTheClientRegistrationIsRejected()
    {
        using var client = factory.CreateClient();
        var (_, challenge) = Oauth.CreatePkce();
        var response = await Oauth.AuthorizeAsync(client, "openid api.write", Oauth.NewNonce(), challenge);

        Assert.Equal(HttpStatusCode.BadRequest, response.Status);
        Assert.Equal("invalid_scope", response.Error);
    }
}
