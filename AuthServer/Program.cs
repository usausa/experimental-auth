using AuthServer.Components;
using AuthServer.Database;
using AuthServer.Endpoints;
using AuthServer.Models;
using AuthServer.Services;

using MudBlazor.Services;

using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddOpenApi(options =>
{
    options.AddDocumentTransformer((doc, _, _) =>
    {
        doc.Info.Title = "AuthServer API";
        doc.Info.Version = "v1";
        doc.Info.Description = "OAuth 2.0 / OpenID Connect 認証サーバーの公開エンドポイント";
        return Task.CompletedTask;
    });
});

builder.Services.Configure<AuthServerOptions>(builder.Configuration.GetSection("AuthServer"));

var dataDirectory = Path.Combine(builder.Environment.ContentRootPath, "Data");

// テストデータの投入は Seed:Enabled で制御する。未設定時は Development 環境のみ有効。
// 既知の資格情報 (test-client / alice など) が本番環境で作られることを防ぐ。
var seedEnabled = builder.Configuration.GetValue("Seed:Enabled", builder.Environment.IsDevelopment());
builder.Services.AddSingleton(sp =>
{
    var factory = new DbConnectionFactory(dataDirectory);
    DatabaseInitializer.Initialize(factory);
    var logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger("DataSeeder");
    if (seedEnabled)
    {
        DataSeeder.Seed(factory, logger);
    }
    else
    {
        logger.LogInformation("Seed data is disabled (Seed:Enabled = false).");
    }

    return factory;
});

builder.Services.AddSingleton<SigningKeyService>();
builder.Services.AddSingleton<ClientService>();
builder.Services.AddSingleton<ResourceServerService>();
builder.Services.AddSingleton<TokenService>();
builder.Services.AddSingleton<UserService>();
builder.Services.AddSingleton<AuthorizationCodeService>();
builder.Services.AddSingleton<RefreshTokenService>();

builder.Services.AddMudServices();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
}
else
{
    app.MapOpenApi("/api-docs/{documentName}.json");
    app.MapScalarApiReference("/api-docs", options =>
    {
        options.WithTitle("AuthServer API")
               .WithOpenApiRoutePattern("/api-docs/{documentName}.json");
    });
}
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.MapDiscoveryEndpoint();
app.MapJwksEndpoint();
app.MapTokenEndpoint();
app.MapAuthorizeEndpoint();
app.MapUserInfoEndpoint();

app.MapDefaultEndpoints();

app.Run();
