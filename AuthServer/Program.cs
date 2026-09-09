using AuthServer.Components;
using AuthServer.Database;
using AuthServer.Endpoints;
using AuthServer.Models;
using AuthServer.Security;
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

// SEC-09 レート制限 / SEC-10 CORS (RateLimiting / Cors セクション)
builder.Services.AddAuthServerRateLimiting(builder.Configuration);
builder.Services.AddAuthServerCors(builder.Configuration);

// SQLite の配置先。Data:Directory で上書きできる (結合テストは一時ディレクトリを使う)。相対パスはコンテンツルート基準
var dataDirectory = Path.GetFullPath(builder.Configuration["Data:Directory"] ?? "Data", builder.Environment.ContentRootPath);

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
builder.Services.AddSingleton<RevokedTokenService>();
builder.Services.AddSingleton<DeviceCodeService>();
builder.Services.AddSingleton<ReplayGuardService>();
builder.Services.AddSingleton<AuditLogService>();
builder.Services.AddSingleton<CustomClaimService>();
builder.Services.AddSingleton<ClientAuthenticator>();

// 期限切れデータのクリーンアップと鍵の自動ローテーション。
// 保守ジョブの例外でホスト全体が停止しないようにする (例外はホストがログに記録する)。
builder.Services.AddHostedService<MaintenanceService>();
builder.Services.Configure<HostOptions>(options =>
{
    options.BackgroundServiceExceptionBehavior = BackgroundServiceExceptionBehavior.Ignore;
});

builder.Services.AddMudServices();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
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

// SEC-01: HTTPS 必須。開発環境は dev 証明書で HTTPS のみをリッスンし、本番相当では HTTP を HTTPS へリダイレクトして HSTS を送る
app.UseHttpsRedirection();
app.UseCors();
app.UseRateLimiter();
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
app.MapRevocationEndpoint();
app.MapIntrospectionEndpoint();
app.MapDeviceAuthorizationEndpoint();

app.MapDefaultEndpoints();

app.Run();
