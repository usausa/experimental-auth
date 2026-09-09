namespace AuthServer.Tests;

using System.Net;
using System.Net.Http.Headers;

using AuthServer.Services;
using AuthServer.Tests.Infrastructure;

using Microsoft.Extensions.DependencyInjection;

// クライアント認証 (RFC 6749 §2.3 / RFC 7523): 登録された方式の強制と private_key_jwt の検証・リプレイ検出
public sealed class ClientAuthenticationTests : IClassFixture<AuthServerFactory>
{
    private const string TokenEndpoint = Oauth.Issuer + "/connect/token";

    private readonly AuthServerFactory factory;

    public ClientAuthenticationTests(AuthServerFactory factory)
    {
        this.factory = factory;
    }

    [Fact]
    public async Task ClientSecretPostIssuesAccessToken()
    {
        using var client = factory.CreateClient();
        var response = await Oauth.ClientCredentialsAsync(client);

        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.Equal("Bearer", response.GetString("token_type"));
        Assert.Equal(900, response.GetInt32("expires_in"));
        Assert.Equal("api.read", response.GetString("scope"));

        var token = response.GetString("access_token")!;
        Assert.Equal("at+jwt", Oauth.JwtHeader(token).GetProperty("typ").GetString());

        var payload = Oauth.JwtPayload(token);
        Assert.Equal(Oauth.Issuer, payload.GetProperty("iss").GetString());
        Assert.Equal("test-client", payload.GetProperty("sub").GetString());
        Assert.Equal("test-client", payload.GetProperty("client_id").GetString());
        Assert.Equal(Oauth.DefaultAudience, payload.GetProperty("aud").GetString());
        Assert.Equal("api.read", payload.GetProperty("scope").GetString());
        Assert.False(String.IsNullOrEmpty(payload.GetProperty("jti").GetString()));
    }

    [Fact]
    public async Task ClientSecretBasicIsAccepted()
    {
        using var client = factory.CreateClient();
        var response = await Oauth.PostFormAsync(
            client, Oauth.TokenPath,
            Oauth.Form(("grant_type", "client_credentials"), ("scope", "api.read")),
            request => request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Oauth.BasicAuthorization("test-client", "test-secret")));

        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.Equal("test-client", Oauth.JwtPayload(response.GetString("access_token")!).GetProperty("client_id").GetString());
    }

    [Theory]
    [InlineData("test-client", "wrong-secret")]
    [InlineData("test-client", "")]
    [InlineData("no-such-client", "test-secret")]
    public async Task InvalidSecretCredentialsAreRejected(string clientId, string clientSecret)
    {
        using var client = factory.CreateClient();
        var response = await Oauth.ClientCredentialsAsync(client, clientId, clientSecret);

        Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
        Assert.Equal("invalid_client", response.Error);
        Assert.False(response.HasProperty("access_token"));
    }

    [Fact]
    public async Task MissingClientIdIsRejected()
    {
        using var client = factory.CreateClient();
        var response = await Oauth.PostFormAsync(client, Oauth.TokenPath, Oauth.Form(("grant_type", "client_credentials")));

        Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
        Assert.Equal("invalid_client", response.Error);
    }

    [Fact]
    public async Task PublicClientMustNotSendASecret()
    {
        using var client = factory.CreateClient();
        var withSecret = await Oauth.PostFormAsync(
            client, Oauth.DeviceAuthorizePath, Oauth.Form(("client_id", "test-device"), ("client_secret", "anything"), ("scope", "openid")));
        Assert.Equal(HttpStatusCode.Unauthorized, withSecret.Status);
        Assert.Equal("invalid_client", withSecret.Error);
        Assert.Contains("public", withSecret.ErrorDescription, StringComparison.Ordinal);

        var withoutSecret = await Oauth.PostFormAsync(client, Oauth.DeviceAuthorizePath, Oauth.Form(("client_id", "test-device"), ("scope", "openid")));
        Assert.Equal(HttpStatusCode.OK, withoutSecret.Status);
        Assert.True(withoutSecret.HasProperty("user_code"));
    }

    [Fact]
    public async Task PrivateKeyJwtClientCannotAuthenticateWithASecret()
    {
        using var client = factory.CreateClient();
        var response = await Oauth.ClientCredentialsAsync(client, "test-jwt-client", "anything");

        Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
        Assert.Equal("invalid_client", response.Error);
        Assert.Contains("private_key_jwt", response.ErrorDescription, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PrivateKeyJwtIssuesTokenAndRejectsReplayOfTheAssertion()
    {
        using var client = factory.CreateClient();
        var assertion = Oauth.CreateClientAssertion("test-jwt-client", TokenEndpoint);

        var first = await Oauth.ClientCredentialsWithAssertionAsync(client, assertion);
        Assert.Equal(HttpStatusCode.OK, first.Status);
        Assert.Equal("test-jwt-client", Oauth.JwtPayload(first.GetString("access_token")!).GetProperty("client_id").GetString());

        var replay = await Oauth.ClientCredentialsWithAssertionAsync(client, assertion);
        Assert.Equal(HttpStatusCode.Unauthorized, replay.Status);
        Assert.Equal("invalid_client", replay.Error);
        Assert.Contains("replay", replay.ErrorDescription, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PrivateKeyJwtAcceptsIssuerIdentifierAsAudience()
    {
        using var client = factory.CreateClient();
        var response = await Oauth.ClientCredentialsWithAssertionAsync(client, Oauth.CreateClientAssertion("test-jwt-client", Oauth.Issuer));

        Assert.Equal(HttpStatusCode.OK, response.Status);
    }

    [Fact]
    public async Task PrivateKeyJwtRejectsWrongAudience()
    {
        using var client = factory.CreateClient();
        var response = await Oauth.ClientCredentialsWithAssertionAsync(client, Oauth.CreateClientAssertion("test-jwt-client", "https://evil.example/token"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
        Assert.Equal("invalid_client", response.Error);
        Assert.Contains("aud", response.ErrorDescription, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PrivateKeyJwtRejectsTamperedSignature()
    {
        using var client = factory.CreateClient();
        var response = await Oauth.ClientCredentialsWithAssertionAsync(client, Oauth.Tamper(Oauth.CreateClientAssertion("test-jwt-client", TokenEndpoint)));

        Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
        Assert.Equal("invalid_client", response.Error);
        Assert.Contains("signature", response.ErrorDescription, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PrivateKeyJwtRejectsUnsupportedAssertionType()
    {
        using var client = factory.CreateClient();
        var response = await Oauth.ClientCredentialsWithAssertionAsync(
            client, Oauth.CreateClientAssertion("test-jwt-client", TokenEndpoint), assertionType: "urn:ietf:params:oauth:client-assertion-type:saml2-bearer");

        Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
        Assert.Equal("invalid_client", response.Error);
        Assert.Contains("client_assertion_type", response.ErrorDescription, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PrivateKeyJwtRejectsClientRegisteredForSecrets()
    {
        using var client = factory.CreateClient();
        var response = await Oauth.ClientCredentialsWithAssertionAsync(client, Oauth.CreateClientAssertion("test-client", TokenEndpoint));

        Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
        Assert.Equal("invalid_client", response.Error);
        Assert.Contains("not registered", response.ErrorDescription, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PrivateKeyJwtRejectsLongLivedAssertion()
    {
        using var client = factory.CreateClient();
        var response = await Oauth.ClientCredentialsWithAssertionAsync(
            client, Oauth.CreateClientAssertion("test-jwt-client", TokenEndpoint, lifetime: TimeSpan.FromMinutes(10)));

        Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
        Assert.Equal("invalid_client", response.Error);
        Assert.Contains("lifetime", response.ErrorDescription, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PrivateKeyJwtWorksForIntrospection()
    {
        using var client = factory.CreateClient();
        var token = (await Oauth.ClientCredentialsWithAssertionAsync(client, Oauth.CreateClientAssertion("test-jwt-client", TokenEndpoint))).GetString("access_token")!;

        var response = await Oauth.PostFormAsync(client, Oauth.IntrospectPath, Oauth.Form(
            ("token", token),
            ("client_assertion_type", Oauth.JwtBearerAssertionType),
            ("client_assertion", Oauth.CreateClientAssertion("test-jwt-client", Oauth.Issuer + "/connect/introspect"))));

        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.True(response.Property("active").GetBoolean());
    }

    [Fact]
    public async Task AuthenticationFailuresAndReplaysAreAuditLogged()
    {
        using var client = factory.CreateClient();
        await Oauth.ClientCredentialsAsync(client, "audit-probe-client", "x");

        var assertion = Oauth.CreateClientAssertion("test-jwt-client", TokenEndpoint);
        await Oauth.ClientCredentialsWithAssertionAsync(client, assertion);
        await Oauth.ClientCredentialsWithAssertionAsync(client, assertion);

        var auditLog = factory.Services.GetRequiredService<AuditLogService>();
        var failures = await auditLog.QueryAsync(new AuditLogFilter(AuditEvents.ClientAuth, AuditOutcome.Failure, "audit-probe-client", null), 10);
        Assert.NotEmpty(failures);

        var replays = await auditLog.QueryAsync(new AuditLogFilter(AuditEvents.ReplayDetected, AuditOutcome.Failure, "test-jwt-client", "jti"), 10);
        Assert.NotEmpty(replays);
    }
}
