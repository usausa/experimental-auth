extern alias ResourceServerApp;

namespace ResourceServer.Tests;

using AuthServer.Tests.Infrastructure;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

// ResourceServer を TestServer 上で起動し、Discovery / JWKS の取得先を AuthServer の TestServer に差し替える。
// ResourceServer の Program は internal (InternalsVisibleTo で参照) で、AuthServer の Program と名前が衝突するため参照を alias で区別する。
public sealed class ResourceServerFactory : WebApplicationFactory<ResourceServerApp::Program>
{
    private readonly AuthServerFactory authServer;
    private HttpClient? backchannel;

    public ResourceServerFactory(AuthServerFactory authServer)
    {
        this.authServer = authServer;
        ClientOptions.BaseAddress = new Uri("https://localhost");
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.ConfigureTestServices(services =>
        {
            services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
            {
                backchannel ??= new HttpClient(authServer.Server.CreateHandler());
                options.RequireHttpsMetadata = false;
                options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                    Oauth.Issuer + "/.well-known/openid-configuration",
                    new OpenIdConnectConfigurationRetriever(),
                    new HttpDocumentRetriever(backchannel) { RequireHttps = false });
            });
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            backchannel?.Dispose();
        }
    }
}

// AuthServer と ResourceServer の 2 つの TestServer をまとめて持つフィクスチャ
public sealed class ResourceServerFixture : IDisposable
{
    public ResourceServerFixture()
    {
        Auth = new AuthServerFactory();
        Api = new ResourceServerFactory(Auth);
    }

    public AuthServerFactory Auth { get; }

    public ResourceServerFactory Api { get; }

    public void Dispose()
    {
        Api.Dispose();
        Auth.Dispose();
    }
}
