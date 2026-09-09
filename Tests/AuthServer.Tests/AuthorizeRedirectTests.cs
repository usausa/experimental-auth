namespace AuthServer.Tests;

using System.Net;

using AuthServer.Tests.Infrastructure;

// 方式 A: GET /connect/authorize (ブラウザリダイレクト) とセッション Cookie。
// ログイン画面は未実装なので、セッションは /account/session で確立する。
public sealed class AuthorizeRedirectTests : IClassFixture<AuthServerFactory>
{
    private const string RedirectTarget = Oauth.RedirectTarget;

    private readonly AuthServerFactory factory;

    public AuthorizeRedirectTests(AuthServerFactory factory)
    {
        this.factory = factory;
    }

    [Fact]
    public async Task SignInEstablishesASessionAndSignOutClearsIt()
    {
        using var client = factory.CreateBrowserClient();

        var anonymous = await Oauth.QuerySessionAsync(client);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.Status);
        Assert.Equal("login_required", anonymous.Error);

        var signIn = await Oauth.SignInAsync(client);
        Assert.Equal(HttpStatusCode.OK, signIn.Status);
        Assert.Equal("user-001", signIn.GetString("sub"));
        Assert.Equal("alice", signIn.GetString("username"));
        var setCookie = signIn.Header("Set-Cookie");
        Assert.NotNull(setCookie);
        Assert.Contains("AuthServer.Session", setCookie, StringComparison.Ordinal);
        Assert.Contains("httponly", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", setCookie, StringComparison.OrdinalIgnoreCase);

        var current = await Oauth.QuerySessionAsync(client);
        Assert.Equal(HttpStatusCode.OK, current.Status);
        Assert.Equal("user-001", current.GetString("sub"));

        Assert.Equal(HttpStatusCode.NoContent, (await Oauth.SignOutAsync(client)).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Oauth.QuerySessionAsync(client)).Status);
    }

    [Fact]
    public async Task SignInWithAWrongPasswordIsRejected()
    {
        using var client = factory.CreateBrowserClient();
        var response = await Oauth.SignInAsync(client, password: "wrong");

        Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
        Assert.Equal("access_denied", response.Error);
        Assert.Null(response.Header("Set-Cookie"));
    }

    [Fact]
    public async Task AuthorizeRedirectsWithTheCodeAndTheCodeCanBeExchanged()
    {
        using var client = factory.CreateBrowserClient();
        var signIn = await Oauth.SignInAsync(client);
        var sessionAuthTime = signIn.Property("auth_time").GetInt64();

        var (verifier, challenge) = Oauth.CreatePkce();
        var nonce = Oauth.NewNonce();
        var response = await Oauth.GetAsync(client, BuildUrl(challenge, "openid profile api.read", nonce, ("state", "state-abc")));

        Assert.Equal(HttpStatusCode.Found, response.Status);
        var location = response.Header("Location");
        Assert.NotNull(location);
        Assert.StartsWith(RedirectTarget + "?", location, StringComparison.Ordinal);

        var parameters = Oauth.ParseRedirect(location);
        Assert.Equal("state-abc", parameters["state"]);
        Assert.False(String.IsNullOrEmpty(parameters["code"]));
        Assert.DoesNotContain("error", parameters.Keys, StringComparer.Ordinal);

        var tokens = await Oauth.ExchangeCodeAsync(client, parameters["code"], verifier);
        Assert.Equal(HttpStatusCode.OK, tokens.Status);

        var idToken = Oauth.JwtPayload(tokens.GetString("id_token")!);
        Assert.Equal("user-001", idToken.GetProperty("sub").GetString());
        Assert.Equal(nonce, idToken.GetProperty("nonce").GetString());

        // 方式 A の auth_time は「コードを発行した時刻」ではなく「セッションでログインした時刻」
        Assert.Equal(sessionAuthTime, idToken.GetProperty("auth_time").GetInt64());
    }

    [Fact]
    public async Task WithoutASessionTheErrorGoesBackToTheRedirectUri()
    {
        using var client = factory.CreateBrowserClient();
        var (_, challenge) = Oauth.CreatePkce();

        var response = await Oauth.GetAsync(client, BuildUrl(challenge, "openid", Oauth.NewNonce(), ("state", "st-1")));

        Assert.Equal(HttpStatusCode.Found, response.Status);
        var parameters = Oauth.ParseRedirect(response.Header("Location"));
        Assert.Equal("login_required", parameters["error"]);
        Assert.Equal("st-1", parameters["state"]);
        Assert.DoesNotContain("code", parameters.Keys, StringComparer.Ordinal);
    }

    [Fact]
    public async Task UnknownClientIsNotRedirected()
    {
        using var client = factory.CreateBrowserClient();
        var (_, challenge) = Oauth.CreatePkce();
        var url = Oauth.BuildAuthorizeUrl(
            ("response_type", "code"),
            ("client_id", "no-such-client"),
            ("redirect_uri", RedirectTarget),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"));

        var response = await Oauth.GetAsync(client, url);

        Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
        Assert.Equal("invalid_client", response.Error);
        Assert.Null(response.Header("Location"));
    }

    [Theory]
    [InlineData("http://evil.example/callback")]
    [InlineData(null)]
    public async Task BadRedirectUriIsNotRedirected(string? redirectTarget)
    {
        using var client = factory.CreateBrowserClient();
        var (_, challenge) = Oauth.CreatePkce();
        var url = Oauth.BuildAuthorizeUrl(
            ("response_type", "code"),
            ("client_id", "test-webapp"),
            ("redirect_uri", redirectTarget),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"));

        var response = await Oauth.GetAsync(client, url);

        Assert.Equal(HttpStatusCode.BadRequest, response.Status);
        Assert.Equal("invalid_request", response.Error);
        Assert.Null(response.Header("Location"));
    }

    [Fact]
    public async Task InvalidResponseTypeIsReturnedOnTheRedirectUri()
    {
        using var client = factory.CreateBrowserClient();
        await Oauth.SignInAsync(client);
        var (_, challenge) = Oauth.CreatePkce();
        var url = Oauth.BuildAuthorizeUrl(
            ("response_type", "token"),
            ("client_id", "test-webapp"),
            ("redirect_uri", RedirectTarget),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
            ("state", "st-2"));

        var response = await Oauth.GetAsync(client, url);

        Assert.Equal(HttpStatusCode.Found, response.Status);
        var parameters = Oauth.ParseRedirect(response.Header("Location"));
        Assert.Equal("unsupported_response_type", parameters["error"]);
        Assert.Equal("st-2", parameters["state"]);
    }

    [Fact]
    public async Task MissingPkceIsReturnedOnTheRedirectUri()
    {
        using var client = factory.CreateBrowserClient();
        await Oauth.SignInAsync(client);
        var url = Oauth.BuildAuthorizeUrl(
            ("response_type", "code"),
            ("client_id", "test-webapp"),
            ("redirect_uri", RedirectTarget),
            ("scope", "api.read"));

        var response = await Oauth.GetAsync(client, url);

        Assert.Equal(HttpStatusCode.Found, response.Status);
        Assert.Equal("invalid_request", Oauth.ParseRedirect(response.Header("Location"))["error"]);
    }

    [Fact]
    public async Task ScopeOutsideTheRegistrationIsReturnedOnTheRedirectUri()
    {
        using var client = factory.CreateBrowserClient();
        await Oauth.SignInAsync(client);
        var (_, challenge) = Oauth.CreatePkce();

        var response = await Oauth.GetAsync(client, BuildUrl(challenge, "openid api.write", Oauth.NewNonce()));

        Assert.Equal(HttpStatusCode.Found, response.Status);
        Assert.Equal("invalid_scope", Oauth.ParseRedirect(response.Header("Location"))["error"]);
    }

    [Fact]
    public async Task OpenIdWithoutNonceIsReturnedOnTheRedirectUri()
    {
        using var client = factory.CreateBrowserClient();
        await Oauth.SignInAsync(client);
        var (_, challenge) = Oauth.CreatePkce();

        var response = await Oauth.GetAsync(client, BuildUrl(challenge, "openid", null));

        Assert.Equal(HttpStatusCode.Found, response.Status);
        var parameters = Oauth.ParseRedirect(response.Header("Location"));
        Assert.Equal("invalid_request", parameters["error"]);
        Assert.Contains("nonce", parameters["error_description"], StringComparison.Ordinal);
    }

    [Fact]
    public async Task NonceReuseIsReturnedOnTheRedirectUri()
    {
        using var client = factory.CreateBrowserClient();
        await Oauth.SignInAsync(client);
        var nonce = Oauth.NewNonce();

        var (_, first) = Oauth.CreatePkce();
        Assert.Equal(HttpStatusCode.Found, (await Oauth.GetAsync(client, BuildUrl(first, "openid", nonce))).Status);

        var (_, second) = Oauth.CreatePkce();
        var response = await Oauth.GetAsync(client, BuildUrl(second, "openid", nonce));
        var parameters = Oauth.ParseRedirect(response.Header("Location"));
        Assert.Equal("invalid_request", parameters["error"]);
        Assert.Contains("already", parameters["error_description"], StringComparison.Ordinal);
    }

    [Fact]
    public async Task PromptNoneSucceedsWithASessionAndFailsWithout()
    {
        using var client = factory.CreateBrowserClient();
        var (_, challenge) = Oauth.CreatePkce();

        var anonymous = await Oauth.GetAsync(client, BuildUrl(challenge, "openid", Oauth.NewNonce(), ("prompt", "none")));
        Assert.Equal("login_required", Oauth.ParseRedirect(anonymous.Header("Location"))["error"]);

        await Oauth.SignInAsync(client);
        var (_, challenge2) = Oauth.CreatePkce();
        var authenticated = await Oauth.GetAsync(client, BuildUrl(challenge2, "openid", Oauth.NewNonce(), ("prompt", "none")));
        Assert.Equal(HttpStatusCode.Found, authenticated.Status);
        Assert.Contains("code", Oauth.ParseRedirect(authenticated.Header("Location")).Keys, StringComparer.Ordinal);
    }

    [Theory]
    [InlineData("none login", "invalid_request")]
    [InlineData("login", "login_required")]
    [InlineData("consent", "consent_required")]
    [InlineData("select_account", "account_selection_required")]
    public async Task PromptValuesThatNeedAScreenAreReported(string prompt, string expectedError)
    {
        using var client = factory.CreateBrowserClient();
        await Oauth.SignInAsync(client);
        var (_, challenge) = Oauth.CreatePkce();

        var response = await Oauth.GetAsync(client, BuildUrl(challenge, "openid", Oauth.NewNonce(), ("prompt", prompt)));

        Assert.Equal(HttpStatusCode.Found, response.Status);
        Assert.Equal(expectedError, Oauth.ParseRedirect(response.Header("Location"))["error"]);
    }

    [Fact]
    public async Task MaxAgeZeroForcesReAuthentication()
    {
        using var client = factory.CreateBrowserClient();
        await Oauth.SignInAsync(client);
        var (_, challenge) = Oauth.CreatePkce();

        // ログイン直後でも max_age=0 は「今この瞬間の認証」を要求するため再認証になる
        await Task.Delay(TimeSpan.FromSeconds(1.1));
        var response = await Oauth.GetAsync(client, BuildUrl(challenge, "openid", Oauth.NewNonce(), ("max_age", "0")));

        Assert.Equal(HttpStatusCode.Found, response.Status);
        var parameters = Oauth.ParseRedirect(response.Header("Location"));
        Assert.Equal("login_required", parameters["error"]);
        Assert.Contains("max_age", parameters["error_description"], StringComparison.Ordinal);
    }

    [Fact]
    public async Task FormPostResponseModeReturnsAnAutoSubmittingForm()
    {
        using var client = factory.CreateBrowserClient();
        await Oauth.SignInAsync(client);
        var (_, challenge) = Oauth.CreatePkce();

        var response = await Oauth.GetAsync(
            client, BuildUrl(challenge, "openid", Oauth.NewNonce(), ("response_mode", "form_post"), ("state", "st-3")));

        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.Contains("text/html", response.Header("Content-Type"), StringComparison.Ordinal);
        Assert.Contains($"<form method=\"post\" action=\"{RedirectTarget}\">", response.Text, StringComparison.Ordinal);
        Assert.Contains("name=\"code\"", response.Text, StringComparison.Ordinal);
        Assert.Contains("value=\"st-3\"", response.Text, StringComparison.Ordinal);
        Assert.Contains("document.forms[0].submit()", response.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UnsupportedResponseModeFallsBackToAQueryErrorRedirect()
    {
        using var client = factory.CreateBrowserClient();
        await Oauth.SignInAsync(client);
        var (_, challenge) = Oauth.CreatePkce();

        var response = await Oauth.GetAsync(client, BuildUrl(challenge, "openid", Oauth.NewNonce(), ("response_mode", "fragment")));

        Assert.Equal(HttpStatusCode.Found, response.Status);
        var parameters = Oauth.ParseRedirect(response.Header("Location"));
        Assert.Equal("invalid_request", parameters["error"]);
        Assert.Contains("response_mode", parameters["error_description"], StringComparison.Ordinal);
    }

    [Fact]
    public async Task ClientWithoutTheAuthorizationCodeGrantIsRejected()
    {
        using var client = factory.CreateBrowserClient();
        await Oauth.SignInAsync(client);
        var (_, challenge) = Oauth.CreatePkce();
        var url = Oauth.BuildAuthorizeUrl(
            ("response_type", "code"),
            ("client_id", "test-device"),
            ("redirect_uri", RedirectTarget),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"));

        var response = await Oauth.GetAsync(client, url);

        // test-device には redirect_uri が登録されていないため、リダイレクトせず直接エラーになる
        Assert.Equal(HttpStatusCode.BadRequest, response.Status);
        Assert.Equal("invalid_request", response.Error);
    }

    [Fact]
    public async Task SignOutStopsTheRedirectFlow()
    {
        using var client = factory.CreateBrowserClient();
        await Oauth.SignInAsync(client);
        var (_, challenge) = Oauth.CreatePkce();
        Assert.Equal(HttpStatusCode.Found, (await Oauth.GetAsync(client, BuildUrl(challenge, "openid", Oauth.NewNonce()))).Status);

        await Oauth.SignOutAsync(client);

        var (_, challenge2) = Oauth.CreatePkce();
        var response = await Oauth.GetAsync(client, BuildUrl(challenge2, "openid", Oauth.NewNonce()));
        Assert.Equal("login_required", Oauth.ParseRedirect(response.Header("Location"))["error"]);
    }

    // OIDC Core §3.1.2.1: 認可エンドポイントは GET と POST の両方に対応する。
    // POST は同じ認可パラメーターを form-urlencoded で受け取り、応答も GET と同じ。
    [Fact]
    public async Task PostAuthorizationRequestBehavesLikeGet()
    {
        using var client = factory.CreateBrowserClient();
        var signIn = await Oauth.SignInAsync(client);
        var (verifier, challenge) = Oauth.CreatePkce();
        var nonce = Oauth.NewNonce();

        var response = await Oauth.PostFormAsync(client, Oauth.AuthorizePath, Oauth.Form(
            ("response_type", "code"),
            ("client_id", "test-webapp"),
            ("redirect_uri", RedirectTarget),
            ("scope", "openid profile"),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
            ("state", "st-post"),
            ("nonce", nonce)));

        Assert.Equal(HttpStatusCode.Found, response.Status);
        var parameters = Oauth.ParseRedirect(response.Header("Location"));
        Assert.Equal("st-post", parameters["state"]);

        var tokens = await Oauth.ExchangeCodeAsync(client, parameters["code"], verifier);
        Assert.Equal(HttpStatusCode.OK, tokens.Status);

        var idToken = Oauth.JwtPayload(tokens.GetString("id_token")!);
        Assert.Equal(nonce, idToken.GetProperty("nonce").GetString());
        Assert.Equal(signIn.Property("auth_time").GetInt64(), idToken.GetProperty("auth_time").GetInt64());
    }

    [Fact]
    public async Task PostAuthorizationRequestWithoutASessionReturnsLoginRequired()
    {
        using var client = factory.CreateBrowserClient();
        var (_, challenge) = Oauth.CreatePkce();

        var response = await Oauth.PostFormAsync(client, Oauth.AuthorizePath, Oauth.Form(
            ("response_type", "code"),
            ("client_id", "test-webapp"),
            ("redirect_uri", RedirectTarget),
            ("scope", "openid"),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
            ("nonce", Oauth.NewNonce())));

        Assert.Equal(HttpStatusCode.Found, response.Status);
        Assert.Equal("login_required", Oauth.ParseRedirect(response.Header("Location"))["error"]);
    }

    [Fact]
    public async Task PostAuthorizationRequestRequiresFormEncoding()
    {
        using var client = factory.CreateBrowserClient();
        await Oauth.SignInAsync(client);

        // Content-Type が付いていない場合はハンドラーに届くので、OAuth 形式のエラーを返す
        var withoutContentType = await Oauth.SendAsync(client, HttpMethod.Post, Oauth.AuthorizePath);
        Assert.Equal(HttpStatusCode.BadRequest, withoutContentType.Status);
        Assert.Equal("invalid_request", withoutContentType.Error);

        // form 以外の Content-Type は ASP.NET Core が Accepts メタデータに基づいて先に 400 で弾く。
        // 本文が OAuth 形式の JSON にならない点は全フォームエンドポイント共通の課題として TODO にある。
        var wrongContentType = await Oauth.SendAsync(client, HttpMethod.Post, Oauth.AuthorizePath, request =>
            request.Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, wrongContentType.Status);
    }

    // 方式 B は標準の POST 認可要求と衝突しないよう別パスに置いている
    [Fact]
    public async Task DirectAuthorizeStillReturnsTheCodeAsJson()
    {
        using var client = factory.CreateBrowserClient();
        var (_, challenge) = Oauth.CreatePkce();

        var response = await Oauth.PostFormAsync(client, Oauth.DirectAuthorizePath, Oauth.Form(
            ("response_type", "code"),
            ("client_id", "test-webapp"),
            ("redirect_uri", RedirectTarget),
            ("scope", "openid"),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
            ("nonce", Oauth.NewNonce()),
            ("username", "alice"),
            ("password", "password")));

        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.False(String.IsNullOrEmpty(response.GetString("code")));
        Assert.Null(response.Header("Location"));
    }

    [Fact]
    public async Task DiscoveryAdvertisesTheSupportedResponseModes()
    {
        using var client = factory.CreateClient();
        var response = await Oauth.GetAsync(client, Oauth.DiscoveryPath);

        var modes = response.GetStringArray("response_modes_supported");
        Assert.Contains("query", modes);
        Assert.Contains("form_post", modes);
    }

    private static string BuildUrl(string codeChallenge, string scope, string? nonce, params (string Key, string? Value)[] extra)
    {
        var parameters = new List<(string Key, string? Value)>
        {
            ("response_type", "code"),
            ("client_id", "test-webapp"),
            ("redirect_uri", RedirectTarget),
            ("scope", scope),
            ("code_challenge", codeChallenge),
            ("code_challenge_method", "S256"),
            ("nonce", nonce)
        };
        parameters.AddRange(extra);
        return Oauth.BuildAuthorizeUrl([.. parameters]);
    }
}
