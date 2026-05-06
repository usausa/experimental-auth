namespace AuthServer.Database;

using System.Globalization;

using AuthServer.Services;

using Dapper;

using Microsoft.Extensions.Logging;

public static class DataSeeder
{
    public static void Seed(DbConnectionFactory factory, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(factory);
        using var connection = factory.OpenConnection();

        var existing = connection.ExecuteScalar<long>("SELECT COUNT(*) FROM clients");
        if (existing > 0)
        {
            logger?.LogInformation("Seed data already present, skipping.");
            return;
        }

        logger?.LogInformation("Seeding initial test data into AuthServer database.");
        var now = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);

        // Test client (confidential, client_credentials)
        connection.Execute("""
            INSERT INTO clients
                (client_id, client_secret_hash, client_name, grant_types, redirect_uris,
                 scopes, token_endpoint_auth_method, post_logout_redirect_uris,
                 is_active, created_at, updated_at)
            VALUES
                (@ClientId, @ClientSecretHash, @ClientName, @GrantTypes, @RedirectUris,
                 @Scopes, @AuthMethod, NULL, 1, @Now, @Now)
            """,
            new
            {
                ClientId = "test-client",
                ClientSecretHash = PasswordHasher.Hash("test-secret"),
                ClientName = "Test Client (client_credentials)",
                GrantTypes = "[\"client_credentials\"]",
                RedirectUris = (string?)null,
                Scopes = "api.read api.write",
                AuthMethod = "client_secret_post",
                Now = now
            });

        // Authorization Code Flow client placeholder for Phase 2
        connection.Execute("""
            INSERT INTO clients
                (client_id, client_secret_hash, client_name, grant_types, redirect_uris,
                 scopes, token_endpoint_auth_method, post_logout_redirect_uris,
                 is_active, created_at, updated_at)
            VALUES
                (@ClientId, @ClientSecretHash, @ClientName, @GrantTypes, @RedirectUris,
                 @Scopes, @AuthMethod, NULL, 1, @Now, @Now)
            """,
            new
            {
                ClientId = "test-webapp",
                ClientSecretHash = PasswordHasher.Hash("webapp-secret"),
                ClientName = "Test Web App (authorization_code)",
                GrantTypes = "[\"authorization_code\",\"refresh_token\"]",
                RedirectUris = "[\"http://localhost:5173/callback\"]",
                Scopes = "openid profile email api.read",
                AuthMethod = "client_secret_post",
                Now = now
            });

        // Default resource server (must be inserted before users)
        connection.Execute("""
            INSERT INTO resource_servers
                (resource_server_id, name, audience, description, is_active, created_at, updated_at)
            VALUES
                (@Id, @Name, @Audience, @Description, 1, @Now, @Now)
            """,
            new
            {
                Id = "resource-server-001",
                Name = "ResourceServer",
                Audience = "http://localhost:5180",
                Description = "Default resource server",
                Now = now
            });

        // Test user
        connection.Execute("""
            INSERT INTO users
                (user_id, resource_server_id, username, password_hash, email, email_verified, name,
                 given_name, family_name, is_active, created_at, updated_at)
            VALUES
                (@UserId, @ResourceServerId, @UserName, @PasswordHash, @Email, 1, @Name, @Given, @Family, 1, @Now, @Now)
            """,
            new
            {
                UserId = "user-001",
                ResourceServerId = "resource-server-001",
                UserName = "alice",
                PasswordHash = PasswordHasher.Hash("password"),
                Email = "alice@example.com",
                Name = "Alice Tester",
                Given = "Alice",
                Family = "Tester",
                Now = now
            });
    }
}
