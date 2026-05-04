using AuthServer.Components;
using AuthServer.Database;
using AuthServer.Endpoints;
using AuthServer.Models;
using AuthServer.Services;
using MudBlazor.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.Configure<AuthServerOptions>(builder.Configuration.GetSection("AuthServer"));

var dataDirectory = Path.Combine(builder.Environment.ContentRootPath, "Data");
builder.Services.AddSingleton(sp =>
{
    var factory = new DbConnectionFactory(dataDirectory);
    DatabaseInitializer.Initialize(factory);
    DataSeeder.Seed(factory, sp.GetRequiredService<ILoggerFactory>().CreateLogger("DataSeeder"));
    return factory;
});

builder.Services.AddSingleton<SigningKeyService>();
builder.Services.AddSingleton<ClientService>();
builder.Services.AddSingleton<TokenService>();
builder.Services.AddSingleton<UserService>();

builder.Services.AddMudServices();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
}
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.MapDiscoveryEndpoint();
app.MapJwksEndpoint();
app.MapTokenEndpoint();

app.Run();
