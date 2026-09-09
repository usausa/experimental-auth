namespace AuthServer.Tests;

using System.Net;

using AuthServer.Tests.Infrastructure;

// レート制限を有効にした AuthServer。テストごとに新しいインスタンスを作り、ウィンドウの共有による干渉を避ける
internal sealed class RateLimitedAuthServerFactory : AuthServerFactory
{
    protected override IEnumerable<KeyValuePair<string, string?>> Settings =>
    [
        new("RateLimiting:Enabled", "true"),
        new("RateLimiting:WindowSeconds", "60"),
        new("RateLimiting:AuthenticationPermitLimit", "3"),
        new("RateLimiting:TokenPermitLimit", "5")
    ];
}

// SEC-09: 認可エンドポイントとトークン系エンドポイントを別々の固定ウィンドウで制限し、超過は 429 + Retry-After
public sealed class RateLimitingTests
{
    [Fact]
    public static async Task AuthorizeEndpointIsLimitedPerWindow()
    {
        var factory = new RateLimitedAuthServerFactory();
        await using (factory.ConfigureAwait(false))
        {
            using var client = factory.CreateClient();
            var (_, challenge) = Oauth.CreatePkce();

            for (var i = 0; i < 3; i++)
            {
                var attempt = await Oauth.AuthorizeAsync(client, "api.read", null, challenge, password: "wrong");
                Assert.Equal(HttpStatusCode.Unauthorized, attempt.Status);
            }

            var limited = await Oauth.AuthorizeAsync(client, "api.read", null, challenge, password: "wrong");
            Assert.Equal(HttpStatusCode.TooManyRequests, limited.Status);
            Assert.Equal("temporarily_unavailable", limited.Error);
            Assert.NotNull(limited.Header("Retry-After"));
        }
    }

    [Fact]
    public static async Task TokenEndpointHasItsOwnBudget()
    {
        var factory = new RateLimitedAuthServerFactory();
        await using (factory.ConfigureAwait(false))
        {
            using var client = factory.CreateClient();

            for (var i = 0; i < 5; i++)
            {
                var attempt = await Oauth.ClientCredentialsAsync(client);
                Assert.Equal(HttpStatusCode.OK, attempt.Status);
            }

            var limited = await Oauth.ClientCredentialsAsync(client);
            Assert.Equal(HttpStatusCode.TooManyRequests, limited.Status);
            Assert.Equal("temporarily_unavailable", limited.Error);

            // 認可エンドポイントと公開メタデータは別枝なので影響を受けない
            var (_, challenge) = Oauth.CreatePkce();
            var authorize = await Oauth.AuthorizeAsync(client, "api.read", null, challenge, password: "wrong");
            Assert.Equal(HttpStatusCode.Unauthorized, authorize.Status);
            Assert.Equal(HttpStatusCode.OK, (await Oauth.GetAsync(client, Oauth.DiscoveryPath)).Status);
        }
    }

    [Fact]
    public static async Task DisabledRateLimitingImposesNoLimit()
    {
        var factory = new AuthServerFactory();
        await using (factory.ConfigureAwait(false))
        {
            using var client = factory.CreateClient();
            var (_, challenge) = Oauth.CreatePkce();

            for (var i = 0; i < 12; i++)
            {
                var attempt = await Oauth.AuthorizeAsync(client, "api.read", null, challenge, password: "wrong");
                Assert.Equal(HttpStatusCode.Unauthorized, attempt.Status);
            }
        }
    }
}
