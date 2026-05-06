namespace AuthServer.Models;

/// <summary>AuthServer configuration loaded from <c>appsettings.json</c>.</summary>
public sealed class AuthServerOptions
{
    /// <summary>Issuer URL advertised in tokens and Discovery metadata.</summary>
    public string Issuer { get; set; } = "http://localhost:5080";

    /// <summary>Access token lifetime in seconds.</summary>
    public int AccessTokenLifetimeSeconds { get; set; } = 3600;
}
