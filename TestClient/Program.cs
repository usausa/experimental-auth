using Microsoft.Extensions.DependencyInjection;

using Smart.CommandLine.Hosting;

using TestClient.Commands;

var builder = CommandHost.CreateBuilder(args);

builder.Services.AddSingleton<HttpClient>();

builder.ConfigureCommands(commands =>
{
    commands.ConfigureRootCommand(root =>
    {
        root.WithDescription("OAuth2/OIDC test client");
    });

    commands.AddCommand<DiscoveryCommand>();
    commands.AddCommand<TokenCommand>();
    commands.AddCommand<RefreshCommand>();
    commands.AddCommand<ApiCommand>();
    commands.AddCommand<UserInfoCommand>();
    commands.AddCommand<IntrospectCommand>();
    commands.AddCommand<RevokeCommand>();
    commands.AddCommand<DeviceCommand>();
});

var host = builder.Build();
return await host.RunAsync();
