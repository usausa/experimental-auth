namespace AuthServer.Database;

using System.Globalization;

using AuthServer.Services;

using Dapper;

using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;

// 開発用のテストデータを投入する。フィクスチャごとに存在確認して不足分だけ INSERT するため、
// 既存 DB に後から追加されたフィクスチャ (test-device など) も次回起動時に補われる。
// パスワード / シークレットのハッシュ化 (PBKDF2 60 万回) は INSERT が必要な場合にだけ行う。
public static class DataSeeder
{
    public static void Seed(DbConnectionFactory factory, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(factory);
        using var connection = factory.OpenConnection();
        var now = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
        var inserted = 0;

        // 機密クライアント: client_credentials
        inserted += EnsureClient(connection, now,
            clientId: "test-client",
            secret: "test-secret",
            clientName: "Test Client (client_credentials)",
            grantTypes: "[\"client_credentials\"]",
            redirectUris: null,
            scopes: "api.read api.write",
            authMethod: "client_secret_post");

        // 機密クライアント: authorization_code (方式 B) + refresh_token
        inserted += EnsureClient(connection, now,
            clientId: "test-webapp",
            secret: "webapp-secret",
            clientName: "Test Web App (authorization_code)",
            grantTypes: "[\"authorization_code\",\"refresh_token\"]",
            redirectUris: "[\"http://localhost:5173/callback\"]",
            scopes: "openid profile email api.read",
            authMethod: "client_secret_post");

        // 公開クライアント (シークレットなし): device_code + refresh_token。CLI / 入力制約デバイス向け
        inserted += EnsureClient(connection, now,
            clientId: "test-device",
            secret: null,
            clientName: "Test Device (device_code, public client)",
            grantTypes: "[\"urn:ietf:params:oauth:grant-type:device_code\",\"refresh_token\"]",
            redirectUris: null,
            scopes: "openid profile email api.read",
            authMethod: "none");

        // 既定のリソースサーバー (users より先に投入する)
        if (connection.ExecuteScalar<long>("SELECT COUNT(*) FROM resource_servers WHERE resource_server_id = @Id", new { Id = "resource-server-001" }) == 0)
        {
            inserted += connection.Execute("""
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
        }

        // テストユーザー
        if (connection.ExecuteScalar<long>("SELECT COUNT(*) FROM users WHERE user_id = @Id OR username = @UserName", new { Id = "user-001", UserName = "alice" }) == 0)
        {
            inserted += connection.Execute("""
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

        if ((logger is not null) && logger.IsEnabled(LogLevel.Information))
        {
            if (inserted > 0)
            {
                logger.LogInformation("Seeded {Count} missing test fixture(s) into AuthServer database.", inserted);
            }
            else
            {
                logger.LogInformation("Seed data already present, nothing to insert.");
            }
        }
    }

    private static int EnsureClient(
        SqliteConnection connection,
        string now,
        string clientId,
        string? secret,
        string clientName,
        string grantTypes,
        string? redirectUris,
        string scopes,
        string authMethod)
    {
        var exists = connection.ExecuteScalar<long>(
            "SELECT COUNT(*) FROM clients WHERE client_id = @ClientId", new { ClientId = clientId });
        if (exists > 0)
        {
            return 0;
        }

        return connection.Execute("""
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
                ClientId = clientId,
                ClientSecretHash = secret is null ? null : PasswordHasher.Hash(secret),
                ClientName = clientName,
                GrantTypes = grantTypes,
                RedirectUris = redirectUris,
                Scopes = scopes,
                AuthMethod = authMethod,
                Now = now
            });
    }
}
