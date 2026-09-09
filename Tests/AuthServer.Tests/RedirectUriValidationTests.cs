namespace AuthServer.Tests;

using System.Globalization;
using System.Net;

using AuthServer.Database;
using AuthServer.Tests.Infrastructure;

using Dapper;

using Microsoft.Extensions.DependencyInjection;

// redirect_uri の検証 (SEC-05)。認可エンドポイントの典型的な脆弱実装への耐性を確認する。
// 完全一致であること、前方一致や正規化で緩まないこと、危険なスキームやフラグメントを弾くこと。
public sealed class RedirectUriValidationTests : IClassFixture<AuthServerFactory>
{
    private const string UnsafeClientId = "test-unsafe-redirect";
    private const string SafeTarget = "http://localhost:5173/ok";

    private readonly AuthServerFactory factory;

    public RedirectUriValidationTests(AuthServerFactory factory)
    {
        this.factory = factory;
    }

    // 登録済みの値に「似ているが違う」URI はすべて拒否される。前方一致やパス正規化で緩めると通ってしまうもの。
    [Theory]
    [InlineData("http://localhost:5173/callback/")]
    [InlineData("http://localhost:5173/callback?extra=1")]
    [InlineData("http://localhost:5173/callback/../callback")]
    [InlineData("http://localhost:5173/callback/sub")]
    [InlineData("http://localhost:5173/Callback")]
    [InlineData("https://localhost:5173/callback")]
    [InlineData("http://localhost:5174/callback")]
    [InlineData("http://evil.example/callback")]
    [InlineData("http://localhost:5173/callback@evil.example")]
    public async Task NearMissRedirectUriIsRejectedWithoutRedirecting(string redirectTarget)
    {
        using var client = factory.CreateBrowserClient();
        await Oauth.SignInAsync(client);
        var (_, challenge) = Oauth.CreatePkce();

        var response = await Oauth.GetAsync(client, Oauth.BuildAuthorizeUrl(
            ("response_type", "code"),
            ("client_id", "test-webapp"),
            ("redirect_uri", redirectTarget),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256")));

        Assert.Equal(HttpStatusCode.BadRequest, response.Status);
        Assert.Equal("invalid_request", response.Error);

        // 攻撃者が指定した URI へは絶対にリダイレクトしない
        Assert.Null(response.Header("Location"));
    }

    // 登録済みの値そのものは、URL エンコードされていても同じ URI として通る
    [Fact]
    public async Task PercentEncodedFormOfTheRegisteredUriIsAccepted()
    {
        using var client = factory.CreateBrowserClient();
        await Oauth.SignInAsync(client);
        var (_, challenge) = Oauth.CreatePkce();

        var response = await Oauth.GetAsync(
            client,
            Oauth.AuthorizePath +
            "?response_type=code&client_id=test-webapp" +
            "&redirect_uri=http%3A%2F%2Flocalhost%3A5173%2Fcallback" +
            $"&code_challenge={challenge}&code_challenge_method=S256&scope=api.read");

        Assert.Equal(HttpStatusCode.Found, response.Status);
        Assert.Contains("code=", response.Header("Location"), StringComparison.Ordinal);
    }

    // 登録側が汚染された場合の保険。危険なスキームやフラグメント付きは、登録済みでもリダイレクト先にしない。
    [Theory]
    [InlineData("javascript:alert(1)")]
    [InlineData("data:text/html,<script>alert(1)</script>")]
    [InlineData("http://localhost:5173/registered#fragment")]
    public async Task RegisteredButUnsafeRedirectUriIsStillRejected(string redirectTarget)
    {
        await EnsureUnsafeClientAsync();
        using var client = factory.CreateBrowserClient();
        await Oauth.SignInAsync(client);
        var (_, challenge) = Oauth.CreatePkce();

        var response = await Oauth.GetAsync(client, Oauth.BuildAuthorizeUrl(
            ("response_type", "code"),
            ("client_id", UnsafeClientId),
            ("redirect_uri", redirectTarget),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256")));

        Assert.Equal(HttpStatusCode.BadRequest, response.Status);
        Assert.Equal("invalid_request", response.Error);
        Assert.Null(response.Header("Location"));
    }

    // 同じクライアントの安全な登録値は通る。上の拒否がクライアント側の問題ではないことの確認。
    [Fact]
    public async Task SafeRedirectUriOfTheSameClientIsAccepted()
    {
        await EnsureUnsafeClientAsync();
        using var client = factory.CreateBrowserClient();
        await Oauth.SignInAsync(client);
        var (_, challenge) = Oauth.CreatePkce();

        var response = await Oauth.GetAsync(client, Oauth.BuildAuthorizeUrl(
            ("response_type", "code"),
            ("client_id", UnsafeClientId),
            ("redirect_uri", SafeTarget),
            ("scope", "api.read"),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256")));

        Assert.Equal(HttpStatusCode.Found, response.Status);
        Assert.StartsWith(SafeTarget + "?", response.Header("Location"), StringComparison.Ordinal);
    }

    // 危険な値が登録されている状況を作るため、テスト用クライアントを直接投入する
    private async Task EnsureUnsafeClientAsync()
    {
        var dbFactory = factory.Services.GetRequiredService<DbConnectionFactory>();
        var connection = dbFactory.OpenConnection();
        await using (connection.ConfigureAwait(false))
        {
            var exists = await connection.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM clients WHERE client_id = @ClientId", new { ClientId = UnsafeClientId }).ConfigureAwait(false);
            if (exists > 0)
            {
                return;
            }

            var now = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
            await connection.ExecuteAsync("""
                INSERT INTO clients
                    (client_id, client_secret_hash, client_name, grant_types, redirect_uris,
                     scopes, token_endpoint_auth_method, post_logout_redirect_uris, jwks, is_active, created_at, updated_at)
                VALUES
                    (@ClientId, NULL, 'Client with unsafe redirect URIs (test fixture)', '["authorization_code"]', @RedirectUris,
                     'api.read', 'none', NULL, NULL, 1, @Now, @Now)
                """,
                new
                {
                    ClientId = UnsafeClientId,
                    RedirectUris = """["javascript:alert(1)","data:text/html,<script>alert(1)</script>","http://localhost:5173/registered#fragment","http://localhost:5173/ok"]""",
                    Now = now
                }).ConfigureAwait(false);
        }
    }
}
