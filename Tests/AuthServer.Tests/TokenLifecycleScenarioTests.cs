namespace AuthServer.Tests;

using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

using AuthServer.Tests.Infrastructure;

// クライアント側の定番パターン「401 を受けたらリフレッシュして 1 回だけリトライする」を
// DelegatingHandler として組み立て、サーバーがこの流れを支えられることを確認する。
// TestClient に同じハンドラーを載せるときの参照実装も兼ねる。
public sealed class TokenLifecycleScenarioTests : IClassFixture<AuthServerFactory>
{
    private readonly AuthServerFactory factory;

    public TokenLifecycleScenarioTests(AuthServerFactory factory)
    {
        this.factory = factory;
    }

    [Fact]
    public async Task UnauthorizedResponseTriggersARefreshAndASingleRetry()
    {
        using var tokenClient = factory.CreateClient();
        var tokens = await Oauth.AuthorizeAndExchangeAsync(tokenClient, "openid profile api.read");
        var accessToken = tokens.GetString("access_token")!;
        var refreshToken = tokens.GetString("refresh_token")!;

        // アクセストークンを失効させる。AuthServer 自身のエンドポイント (UserInfo) は失効を参照するので 401 になる
        Assert.Equal(HttpStatusCode.OK, (await Oauth.RevokeAsync(tokenClient, accessToken, "access_token")).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Oauth.UserInfoAsync(tokenClient, accessToken)).Status);

        using var handler = new AutoRefreshHandler(factory.Server.CreateHandler(), tokenClient, accessToken, refreshToken);
        using var client = new HttpClient(handler, disposeHandler: false) { BaseAddress = new Uri(Oauth.Issuer) };

        using var response = await client.GetAsync(new Uri(Oauth.UserInfoPath, UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, handler.RefreshCount);
        Assert.NotEqual(accessToken, handler.AccessToken);

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("user-001", document.RootElement.GetProperty("sub").GetString());
    }

    [Fact]
    public async Task ARefreshFailureIsNotRetriedForever()
    {
        using var tokenClient = factory.CreateClient();
        var tokens = await Oauth.AuthorizeAndExchangeAsync(tokenClient, "openid api.read");
        var accessToken = tokens.GetString("access_token")!;
        var refreshToken = tokens.GetString("refresh_token")!;

        // アクセストークンもリフレッシュトークンも失効させる。リフレッシュできないので 401 のままになる
        await Oauth.RevokeAsync(tokenClient, accessToken, "access_token");
        await Oauth.RevokeAsync(tokenClient, refreshToken, "refresh_token");

        using var handler = new AutoRefreshHandler(factory.Server.CreateHandler(), tokenClient, accessToken, refreshToken);
        using var client = new HttpClient(handler, disposeHandler: false) { BaseAddress = new Uri(Oauth.Issuer) };

        using var response = await client.GetAsync(new Uri(Oauth.UserInfoPath, UriKind.Relative));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, handler.RefreshCount);
    }
}

// 401 を受けたらリフレッシュトークンで再取得し、元の要求を 1 回だけ送り直すハンドラー。
//   - HttpRequestMessage は再送できないためクローンする
//   - 同時に複数の要求が 401 になってもリフレッシュが多重実行されないよう直列化する
internal sealed class AutoRefreshHandler : DelegatingHandler
{
    private readonly HttpClient tokenClient;
    private readonly SemaphoreSlim gate = new(1, 1);

    public AutoRefreshHandler(HttpMessageHandler innerHandler, HttpClient tokenClient, string accessToken, string refreshToken)
        : base(innerHandler)
    {
        this.tokenClient = tokenClient;
        AccessToken = accessToken;
        RefreshToken = refreshToken;
    }

    public string AccessToken { get; private set; }

    public string RefreshToken { get; private set; }

    public int RefreshCount { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", AccessToken);
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.Unauthorized)
        {
            return response;
        }

        if (!await TryRefreshAsync().ConfigureAwait(false))
        {
            return response;
        }

        response.Dispose();

        var retry = Clone(request);
        try
        {
            retry.Headers.Authorization = new AuthenticationHeaderValue("Bearer", AccessToken);
            return await base.SendAsync(retry, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            retry.Dispose();
        }
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            gate.Dispose();
        }
    }

    private async Task<bool> TryRefreshAsync()
    {
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            var refreshed = await Oauth.RefreshAsync(tokenClient, RefreshToken).ConfigureAwait(false);
            if (refreshed.Status != HttpStatusCode.OK)
            {
                return false;
            }

            AccessToken = refreshed.GetString("access_token")!;
            RefreshToken = refreshed.GetString("refresh_token") ?? RefreshToken;
            RefreshCount++;
            return true;
        }
        finally
        {
            gate.Release();
        }
    }

    // 本文のない要求を前提にした最小限のクローン
    private static HttpRequestMessage Clone(HttpRequestMessage request)
    {
        var clone = new HttpRequestMessage(request.Method, request.RequestUri);
        foreach (var header in request.Headers)
        {
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        return clone;
    }
}
