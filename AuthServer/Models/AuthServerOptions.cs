namespace AuthServer.Models;

public sealed class AuthServerOptions
{
    public string Issuer { get; set; } = "http://localhost:5080";

    public int AccessTokenLifetimeSeconds { get; set; } = 3600;
}
