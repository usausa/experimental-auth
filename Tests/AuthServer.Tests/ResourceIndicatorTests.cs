namespace AuthServer.Tests;

using System.Net;
using System.Text.Json;

using AuthServer.Models;
using AuthServer.Services;
using AuthServer.Tests.Infrastructure;

using Microsoft.Extensions.DependencyInjection;

// Resource Indicators (RFC 8707): resource を登録済みリソースサーバーの audience に解決し、refresh では元の範囲内に絞り込める
public sealed class ResourceIndicatorTests : IClassFixture<AuthServerFactory>
{
    private const string SecondAudience = "https://localhost:5181";

    private readonly AuthServerFactory factory;

    public ResourceIndicatorTests(AuthServerFactory factory)
    {
        this.factory = factory;
    }

    [Theory]
    [InlineData("https://unknown.example")]
    [InlineData("api")]
    [InlineData("https://localhost:5180#fragment")]
    public async Task InvalidResourceIsRejected(string resource)
    {
        using var client = factory.CreateClient();
        var response = await Oauth.ClientCredentialsAsync(client, extra: ("resource", resource));

        Assert.Equal(HttpStatusCode.BadRequest, response.Status);
        Assert.Equal("invalid_target", response.Error);
    }

    [Fact]
    public async Task SingleResourceYieldsAStringAudience()
    {
        using var client = factory.CreateClient();
        var response = await Oauth.ClientCredentialsAsync(client, extra: ("resource", Oauth.DefaultAudience));

        Assert.Equal(HttpStatusCode.OK, response.Status);
        var aud = Oauth.JwtPayload(response.GetString("access_token")!).GetProperty("aud");
        Assert.Equal(JsonValueKind.String, aud.ValueKind);
        Assert.Equal(Oauth.DefaultAudience, aud.GetString());
    }

    [Fact]
    public async Task MultipleResourcesYieldAnArrayAudience()
    {
        await EnsureSecondResourceServerAsync();
        using var client = factory.CreateClient();
        var response = await Oauth.PostFormAsync(client, Oauth.TokenPath,
        [
            new("grant_type", "client_credentials"),
            new("client_id", "test-client"),
            new("client_secret", "test-secret"),
            new("scope", "api.read"),
            new("resource", Oauth.DefaultAudience),
            new("resource", SecondAudience)
        ]);

        Assert.Equal(HttpStatusCode.OK, response.Status);
        var aud = Oauth.JwtPayload(response.GetString("access_token")!).GetProperty("aud");
        Assert.Equal(JsonValueKind.Array, aud.ValueKind);
        var audiences = aud.EnumerateArray().Select(a => a.GetString()).ToList();
        Assert.Contains(Oauth.DefaultAudience, audiences);
        Assert.Contains(SecondAudience, audiences);

        var introspection = await Oauth.IntrospectAsync(client, response.GetString("access_token")!, clientId: "test-client", clientSecret: "test-secret");
        Assert.Equal(JsonValueKind.Array, introspection.Property("aud").ValueKind);
    }

    [Fact]
    public async Task RefreshKeepsTheAudienceAndCanNarrowButNotWidenIt()
    {
        await EnsureSecondResourceServerAsync();
        using var client = factory.CreateClient();
        var (verifier, challenge) = Oauth.CreatePkce();
        var authorize = await Oauth.AuthorizeAsync(client, "openid api.read", Oauth.NewNonce(), challenge);
        var tokens = await Oauth.PostFormAsync(client, Oauth.TokenPath,
        [
            new("grant_type", "authorization_code"),
            new("client_id", "test-webapp"),
            new("client_secret", "webapp-secret"),
            new("code", authorize.GetString("code")!),
            new("redirect_uri", Oauth.RedirectTarget),
            new("code_verifier", verifier),
            new("resource", Oauth.DefaultAudience),
            new("resource", SecondAudience)
        ]);
        Assert.Equal(HttpStatusCode.OK, tokens.Status);
        Assert.Equal(JsonValueKind.Array, Oauth.JwtPayload(tokens.GetString("access_token")!).GetProperty("aud").ValueKind);

        // resource を省略すると元の audience を維持する
        var kept = await Oauth.RefreshAsync(client, tokens.GetString("refresh_token")!);
        Assert.Equal(HttpStatusCode.OK, kept.Status);
        Assert.Equal(2, Oauth.JwtPayload(kept.GetString("access_token")!).GetProperty("aud").GetArrayLength());

        // 元の範囲内への絞り込みは可能
        var narrowed = await Oauth.RefreshAsync(client, kept.GetString("refresh_token")!, extra: ("resource", SecondAudience));
        Assert.Equal(HttpStatusCode.OK, narrowed.Status);
        Assert.Equal(SecondAudience, Oauth.JwtPayload(narrowed.GetString("access_token")!).GetProperty("aud").GetString());

        // リフレッシュトークンは最初の付与範囲を保持するので、その範囲内なら別の audience に戻せる
        var widened = await Oauth.RefreshAsync(client, narrowed.GetString("refresh_token")!, extra: ("resource", Oauth.DefaultAudience));
        Assert.Equal(HttpStatusCode.OK, widened.Status);
        Assert.Equal(Oauth.DefaultAudience, Oauth.JwtPayload(widened.GetString("access_token")!).GetProperty("aud").GetString());

        // 付与範囲の外 (未登録の audience) は invalid_target
        var outside = await Oauth.RefreshAsync(client, widened.GetString("refresh_token")!, extra: ("resource", "https://localhost:5182"));
        Assert.Equal(HttpStatusCode.BadRequest, outside.Status);
        Assert.Equal("invalid_target", outside.Error);
    }

    private async Task EnsureSecondResourceServerAsync()
    {
        var service = factory.Services.GetRequiredService<ResourceServerService>();
        if (!await service.AudienceExistsAsync(SecondAudience).ConfigureAwait(false))
        {
            await service.CreateAsync(new ResourceServer
            {
                Name = "Second Resource Server",
                Audience = SecondAudience,
                Description = "created by ResourceIndicatorTests",
                IsActive = true
            }).ConfigureAwait(false);
        }
    }
}
