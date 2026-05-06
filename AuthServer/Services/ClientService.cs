namespace AuthServer.Services;

using System.Globalization;
using AuthServer.Database;
using AuthServer.Models;
using Dapper;

public sealed class ClientService(DbConnectionFactory dbFactory)
{
    private const string SelectColumns = """
        client_id              AS ClientId,
        client_secret_hash     AS ClientSecretHash,
        client_name            AS ClientName,
        grant_types            AS GrantTypes,
        redirect_uris          AS RedirectUris,
        scopes                 AS Scopes,
        token_endpoint_auth_method AS TokenEndpointAuthMethod,
        post_logout_redirect_uris  AS PostLogoutRedirectUris,
        is_active              AS IsActive,
        created_at             AS CreatedAt,
        updated_at             AS UpdatedAt
        """;

    public async Task<Client?> FindByIdAsync(string clientId)
    {
        await using var connection = dbFactory.OpenConnection();
        return await connection.QueryFirstOrDefaultAsync<Client>(
            $"SELECT {SelectColumns} FROM clients WHERE client_id = @ClientId AND is_active = 1",
            new { ClientId = clientId });
    }

    public static bool ValidateSecret(Client client, string? secret)
    {
        ArgumentNullException.ThrowIfNull(client);
        if (string.IsNullOrEmpty(client.ClientSecretHash))
        {
            return string.IsNullOrEmpty(secret);
        }
        return !string.IsNullOrEmpty(secret) && PasswordHasher.Verify(secret, client.ClientSecretHash);
    }

    public static string FormatDateTime(DateTime value) =>
        value.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);
}
