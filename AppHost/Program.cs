var builder = DistributedApplication.CreateBuilder(args);

var authServer = builder.AddProject<Projects.AuthServer>("auth-server");

builder.AddProject<Projects.ResourceServer>("resource-server")
    .WithReference(authServer)
    .WaitFor(authServer);

builder.Build().Run();
