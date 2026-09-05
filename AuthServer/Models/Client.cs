namespace AuthServer.Models;

using System.Text.Json;

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

    // grant_types は JSON 配列文字列で保存されている。文字列の部分一致 (Contains) では
    // "client_credentials_jwt" のような値にも一致してしまうため、配列に展開して完全一致で判定する。
    public bool AllowsGrantType(string grantType)
    {
        try
        {
            var allowed = JsonSerializer.Deserialize<string[]>(GrantTypes) ?? [];
            return Array.Exists(allowed, g => String.Equals(g, grantType, StringComparison.Ordinal));
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
