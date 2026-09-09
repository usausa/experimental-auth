namespace AuthServer.Tests;

using System.Net;

using AuthServer.Services;
using AuthServer.Tests.Infrastructure;

using Microsoft.Extensions.DependencyInjection;

// Device Authorization Grant (RFC 8628)。承認画面の操作は DeviceCodeService を直接呼んで代替する
public sealed class DeviceFlowTests : IClassFixture<AuthServerFactory>
{
    private const string UserCodePattern = "^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$";

    private readonly AuthServerFactory factory;

    public DeviceFlowTests(AuthServerFactory factory)
    {
        this.factory = factory;
    }

    [Fact]
    public async Task DeviceFlowIssuesTokensAfterApproval()
    {
        using var client = factory.CreateClient();
        var start = await StartAsync(client, "openid profile api.read");

        Assert.Equal(HttpStatusCode.OK, start.Status);
        var userCode = start.GetString("user_code")!;
        var deviceCode = start.GetString("device_code")!;
        Assert.Matches(UserCodePattern, userCode);
        Assert.Equal(Oauth.Issuer + "/account/device", start.GetString("verification_uri"));
        Assert.Contains(userCode, start.GetString("verification_uri_complete"), StringComparison.Ordinal);
        Assert.Equal(600, start.GetInt32("expires_in"));
        Assert.Equal(1, start.GetInt32("interval"));

        var pending = await Oauth.PollDeviceAsync(client, deviceCode);
        Assert.Equal(HttpStatusCode.BadRequest, pending.Status);
        Assert.Equal("authorization_pending", pending.Error);

        // interval 未満の再ポーリングは slow_down
        var tooFast = await Oauth.PollDeviceAsync(client, deviceCode);
        Assert.Equal("slow_down", tooFast.Error);

        var service = factory.Services.GetRequiredService<DeviceCodeService>();
        Assert.Equal(DeviceApprovalResult.Approved, await service.ApproveAsync(userCode, "user-001"));

        await Task.Delay(TimeSpan.FromSeconds(1.5));
        var tokens = await Oauth.PollDeviceAsync(client, deviceCode);
        Assert.Equal(HttpStatusCode.OK, tokens.Status);
        Assert.False(String.IsNullOrEmpty(tokens.GetString("refresh_token")));

        var access = Oauth.JwtPayload(tokens.GetString("access_token")!);
        Assert.Equal("user-001", access.GetProperty("sub").GetString());
        Assert.Equal("test-device", access.GetProperty("client_id").GetString());

        var idToken = Oauth.JwtPayload(tokens.GetString("id_token")!);
        Assert.Equal("test-device", idToken.GetProperty("aud").GetString());
        Assert.True(idToken.TryGetProperty("auth_time", out _));
        Assert.False(idToken.TryGetProperty("nonce", out _), "the device flow request carries no nonce");

        // 承認済みコードの交換は 1 回限り
        var again = await Oauth.PollDeviceAsync(client, deviceCode);
        Assert.Equal(HttpStatusCode.BadRequest, again.Status);
        Assert.Equal("invalid_grant", again.Error);
    }

    [Fact]
    public async Task DeniedRequestReturnsAccessDenied()
    {
        using var client = factory.CreateClient();
        var start = await StartAsync(client, "openid");
        var service = factory.Services.GetRequiredService<DeviceCodeService>();
        Assert.Equal(DeviceApprovalResult.Denied, await service.DenyAsync(start.GetString("user_code")!));

        var poll = await Oauth.PollDeviceAsync(client, start.GetString("device_code")!);
        Assert.Equal(HttpStatusCode.BadRequest, poll.Status);
        Assert.Equal("access_denied", poll.Error);
    }

    [Fact]
    public async Task DeviceCodeCannotBePolledByAnotherClient()
    {
        using var client = factory.CreateClient();
        var start = await StartAsync(client, "openid");

        var otherClient = await Oauth.PollDeviceAsync(client, start.GetString("device_code")!, "test-webapp", "webapp-secret");
        Assert.Equal(HttpStatusCode.BadRequest, otherClient.Status);
        Assert.Equal("unauthorized_client", otherClient.Error);
    }

    [Fact]
    public async Task ClientWithoutTheDeviceGrantCannotStartTheFlow()
    {
        using var client = factory.CreateClient();
        var response = await Oauth.PostFormAsync(client, Oauth.DeviceAuthorizePath, Oauth.Form(("client_id", "test-client"), ("client_secret", "test-secret")));

        Assert.Equal(HttpStatusCode.BadRequest, response.Status);
        Assert.Equal("unauthorized_client", response.Error);
    }

    [Fact]
    public async Task UnknownDeviceCodeIsRejected()
    {
        using var client = factory.CreateClient();
        var response = await Oauth.PollDeviceAsync(client, "no-such-device-code");

        Assert.Equal(HttpStatusCode.BadRequest, response.Status);
        Assert.Equal("invalid_grant", response.Error);
    }

    [Fact]
    public async Task ScopeOutsideTheClientRegistrationIsRejected()
    {
        using var client = factory.CreateClient();
        var response = await StartAsync(client, "openid api.write");

        Assert.Equal(HttpStatusCode.BadRequest, response.Status);
        Assert.Equal("invalid_scope", response.Error);
    }

    private static Task<OauthResponse> StartAsync(HttpClient client, string scope) =>
        Oauth.PostFormAsync(client, Oauth.DeviceAuthorizePath, Oauth.Form(("client_id", "test-device"), ("scope", scope)));
}
