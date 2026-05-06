namespace AuthServer.Database;

using Dapper;

public static class DatabaseInitializer
{
    private const string Schema = """
        CREATE TABLE IF NOT EXISTS clients (
            client_id TEXT PRIMARY KEY,
            client_secret_hash TEXT,
            client_name TEXT NOT NULL,
            grant_types TEXT NOT NULL,
            redirect_uris TEXT,
            scopes TEXT NOT NULL,
            token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_post',
            post_logout_redirect_uris TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            resource_server_id TEXT NOT NULL REFERENCES resource_servers(resource_server_id),
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT,
            email_verified INTEGER NOT NULL DEFAULT 0,
            name TEXT,
            given_name TEXT,
            family_name TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS authorization_codes (
            code_hash TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            scopes TEXT NOT NULL,
            code_challenge TEXT,
            code_challenge_method TEXT,
            nonce TEXT,
            state TEXT,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS refresh_tokens (
            token_hash TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            scopes TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            is_revoked INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            replaced_by_token_hash TEXT
        );

        CREATE TABLE IF NOT EXISTS device_codes (
            device_code_hash TEXT PRIMARY KEY,
            user_code TEXT NOT NULL UNIQUE,
            client_id TEXT NOT NULL,
            scopes TEXT NOT NULL,
            user_id TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            expires_at TEXT NOT NULL,
            last_polled_at TEXT,
            poll_interval INTEGER NOT NULL DEFAULT 5,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS consents (
            user_id TEXT NOT NULL,
            client_id TEXT NOT NULL,
            scopes TEXT NOT NULL,
            granted_at TEXT NOT NULL,
            PRIMARY KEY (user_id, client_id)
        );

        CREATE TABLE IF NOT EXISTS revoked_tokens (
            jti TEXT PRIMARY KEY,
            token_type TEXT NOT NULL,
            revoked_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS signing_keys (
            kid TEXT PRIMARY KEY,
            algorithm TEXT NOT NULL DEFAULT 'RS256',
            private_key_pem TEXT NOT NULL,
            public_key_pem TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            expires_at TEXT
        );

        CREATE TABLE IF NOT EXISTS resource_servers (
            resource_server_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            audience TEXT NOT NULL UNIQUE,
            description TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """;

    public static void Initialize(DbConnectionFactory factory)
    {
        ArgumentNullException.ThrowIfNull(factory);
        using var connection = factory.OpenConnection();
        connection.Execute(Schema);
    }
}
