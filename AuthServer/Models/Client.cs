namespace AuthServer.Models;

// OAuth 2.0 / OIDC client registration record.
public sealed class Client
{
    public string ClientId { get; set; } = default!;
    public string? ClientSecretHash { get; set; }
    public string ClientName { get; set; } = default!;
    public string GrantTypes { get; set; } = "[]";
    public string? RedirectUris { get; set; }
    public string Scopes { get; set; } = string.Empty;
    public string TokenEndpointAuthMethod { get; set; } = "client_secret_post";
    public string? PostLogoutRedirectUris { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}
