namespace AuthServer.Models;

/// <summary>AuthServer configuration loaded from <c>appsettings.json</c>.</summary>
public sealed class AuthServerOptions
{
    /// <summary>Issuer URL advertised in tokens and Discovery metadata.</summary>
    public string Issuer { get; set; } = "http://localhost:5051";

    /// <summary>Audience used for access tokens (the resource server URL).</summary>
    public string DefaultAudience { get; set; } = "http://localhost:5132";

    /// <summary>Access token lifetime in seconds.</summary>
    public int AccessTokenLifetimeSeconds { get; set; } = 3600;
}
