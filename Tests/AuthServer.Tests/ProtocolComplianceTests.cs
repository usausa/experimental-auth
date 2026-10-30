namespace AuthServer.Tests;

using System.Net;
using System.Net.Http.Headers;

using AuthServer.Tests.Infrastructure;

// 仕様が MUST としている細部の確認。
//   RFC 6749 §5.1  トークン・資格情報を含む応答はキャッシュさせない
//   RFC 9110 §15.5.2 / RFC 6749 §5.2  401 には WWW-Authenticate を添える
//   OIDC Core §5.3.1  UserInfo は GET と POST の両方に対応する
//   RFC 6749 §6  リフレッシュ時のスコープは元の付与範囲のサブセットに限る
public sealed class ProtocolComplianceTests : IClassFixture<AuthServerFactory>
{
    private readonly AuthServerFactory factory;

    public ProtocolComplianceTests(AuthServerFactory factory)
    {
        this.factory = factory;
    }

    [Theory]
    [InlineData("POST", Oauth.TokenPath)]
    [InlineData("POST", Oauth.AuthorizePath)]
    [InlineData("GET", Oauth.AuthorizePath)]
    [InlineData("GET", Oauth.UserInfoPath)]
    [InlineData("POST", Oauth.UserInfoPath)]
    [InlineData("POST", Oauth.RevokePath)]
    [InlineData("POST", Oauth.IntrospectPath)]
    [InlineData("POST", Oauth.DeviceAuthorizePath)]
    [InlineData("POST", Oauth.SessionPath)]
    [InlineData("GET", Oauth.SessionPath)]
    public async Task SensitiveResponsesAreNotCacheable(string method, string path)
    {
        using var client = factory.CreateClient();

        // 成否によらずヘッダーが付くことを見たいので、最小限の要求で足りる
        var response = await Oauth.SendAsync(client, new HttpMethod(method), path);

        Assert.Equal("no-store", response.Header("Cache-Control"));
        Assert.Equal("no-cache", response.Header("Pragma"));
    }

    [Theory]
    [InlineData(Oauth.DiscoveryPath)]
    [InlineData(Oauth.JwksPath)]
    public async Task PublicMetadataStaysCacheable(string path)
    {
        using var client = factory.CreateClient();
        var response = await Oauth.GetAsync(client, path);

        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.NotEqual("no-store", response.Header("Cache-Control"));
    }

    [Theory]
    [InlineData(Oauth.TokenPath)]
    [InlineData(Oauth.RevokePath)]
    [InlineData(Oauth.IntrospectPath)]
    [InlineData(Oauth.DeviceAuthorizePath)]
    public async Task ClientAuthenticationFailureCarriesAChallenge(string path)
    {
        using var client = factory.CreateClient();
        var response = await Oauth.PostFormAsync(client, path, Oauth.Form(
            ("grant_type", "client_credentials"),
            ("token", "irrelevant"),
            ("client_id", "test-client"),
            ("client_secret", "wrong-secret")));

        Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
        var challenge = response.Header("WWW-Authenticate");
        Assert.NotNull(challenge);
        Assert.StartsWith("Basic ", challenge, StringComparison.Ordinal);
    }

    // SEC-15: 全応答に共通のセキュリティヘッダーが載る
    [Theory]
    [InlineData(Oauth.DiscoveryPath)]
    [InlineData(Oauth.JwksPath)]
    [InlineData(Oauth.UserInfoPath)]
    [InlineData("/")]
    public async Task SecurityHeadersArePresent(string path)
    {
        using var client = factory.CreateClient();
        var response = await Oauth.GetAsync(client, path);

        Assert.Equal("nosniff", response.Header("X-Content-Type-Options"));
        Assert.Equal("DENY", response.Header("X-Frame-Options"));

        // 認可コードを含む URL がリファラーとして外部へ渡らないようにする
        Assert.Equal("no-referrer", response.Header("Referrer-Policy"));
        Assert.NotNull(response.Header("Permissions-Policy"));

        var csp = response.Header("Content-Security-Policy");
        Assert.NotNull(csp);
        Assert.Contains("frame-ancestors 'none'", csp, StringComparison.Ordinal);
        Assert.Contains("object-src 'none'", csp, StringComparison.Ordinal);
    }

    // form_post の応答だけは相手先へ POST するため、専用の CSP で form-action と自動送信スクリプトを許可する
    [Fact]
    public async Task FormPostResponseCarriesItsOwnContentSecurityPolicy()
    {
        using var client = factory.CreateBrowserClient();
        await Oauth.SignInAsync(client);
        var (_, challenge) = Oauth.CreatePkce();

        var response = await Oauth.GetAsync(client, Oauth.BuildAuthorizeUrl(
            ("response_type", "code"),
            ("client_id", "test-webapp"),
            ("redirect_uri", Oauth.RedirectTarget),
            ("scope", "openid"),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
            ("nonce", Oauth.NewNonce()),
            ("response_mode", "form_post")));

        Assert.Equal(HttpStatusCode.OK, response.Status);
        var csp = response.Header("Content-Security-Policy");
        Assert.NotNull(csp);
        Assert.Contains("form-action http://localhost:5173", csp, StringComparison.Ordinal);
        Assert.Contains("script-src 'sha256-", csp, StringComparison.Ordinal);

        // インライン属性ではなく <script> ブロックにしてハッシュで許可している
        Assert.Contains("<script>document.forms[0].submit();</script>", response.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("onload=", response.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UserInfoAcceptsTheAccessTokenInTheFormBody()
    {
        using var client = factory.CreateClient();
        var tokens = await Oauth.AuthorizeAndExchangeAsync(client, "openid profile");

        var response = await Oauth.PostFormAsync(
            client, Oauth.UserInfoPath, Oauth.Form(("access_token", tokens.GetString("access_token")!)));

        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.Equal("user-001", response.GetString("sub"));
        Assert.Equal("alice", response.GetString("preferred_username"));
    }

    [Fact]
    public async Task UserInfoAcceptsTheAuthorizationHeaderOnPost()
    {
        using var client = factory.CreateClient();
        var accessToken = (await Oauth.AuthorizeAndExchangeAsync(client, "openid")).GetString("access_token");

        var response = await Oauth.PostFormAsync(
            client, Oauth.UserInfoPath, Oauth.Form(),
            request => request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken));

        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.Equal("user-001", response.GetString("sub"));
    }

    [Fact]
    public async Task UserInfoRejectsTheTokenBeingSentTwice()
    {
        using var client = factory.CreateClient();
        var accessToken = (await Oauth.AuthorizeAndExchangeAsync(client, "openid")).GetString("access_token")!;

        var response = await Oauth.PostFormAsync(
            client, Oauth.UserInfoPath, Oauth.Form(("access_token", accessToken)),
            request => request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken));

        Assert.Equal(HttpStatusCode.BadRequest, response.Status);
        Assert.Equal("invalid_request", response.Error);
    }

    [Fact]
    public async Task UserInfoPostWithoutATokenIsUnauthorized()
    {
        using var client = factory.CreateClient();
        var response = await Oauth.PostFormAsync(client, Oauth.UserInfoPath, Oauth.Form());

        Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
        Assert.Equal("invalid_token", response.Error);
    }

    [Fact]
    public async Task RefreshCanNarrowTheScopeWhileTheGrantKeepsItsOriginalRange()
    {
        using var client = factory.CreateClient();
        var tokens = await Oauth.AuthorizeAndExchangeAsync(client, "openid profile api.read");

        // 元の付与範囲のサブセットに絞る
        var narrowed = await Oauth.RefreshAsync(client, tokens.GetString("refresh_token")!, extra: ("scope", "api.read"));
        Assert.Equal(HttpStatusCode.OK, narrowed.Status);
        Assert.Equal("api.read", narrowed.GetString("scope"));
        Assert.Equal("api.read", Oauth.JwtPayload(narrowed.GetString("access_token")!).GetProperty("scope").GetString());

        // リフレッシュトークンは元の範囲を保持しているので、次回 scope を省略すると元に戻る
        var restored = await Oauth.RefreshAsync(client, narrowed.GetString("refresh_token")!);
        Assert.Equal(HttpStatusCode.OK, restored.Status);
        Assert.Equal("openid profile api.read", restored.GetString("scope"));
    }

    [Fact]
    public async Task RefreshCannotWidenBeyondTheOriginalGrant()
    {
        using var client = factory.CreateClient();
        var tokens = await Oauth.AuthorizeAndExchangeAsync(client, "openid api.read");

        // email はクライアントには許可されているが、この付与には含まれていない
        var response = await Oauth.RefreshAsync(client, tokens.GetString("refresh_token")!, extra: ("scope", "openid email"));

        Assert.Equal(HttpStatusCode.BadRequest, response.Status);
        Assert.Equal("invalid_scope", response.Error);
        Assert.Contains("outside the original grant", response.ErrorDescription, StringComparison.Ordinal);
    }
}
