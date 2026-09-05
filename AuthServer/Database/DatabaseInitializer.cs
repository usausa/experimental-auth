namespace AuthServer.Database;

using System.Globalization;

using Dapper;

public static class DatabaseInitializer
{
    // 基本スキーマ (v0)。既存 DB との整合性を保つため、この定義は変更しない。
    // スキーマ変更は Migrations に追記し、schema_migrations テーブルで適用済みバージョンを管理する。
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

        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        );
        """;

    // スキーマ変更の履歴。バージョン順に、未適用のものだけがトランザクション内で実行される。
    private static readonly (int Version, string Sql)[] Migrations =
    [
        // v1: 認可コードの消費時刻。DELETE ではなく消費済みマークにし、再提示 (漏洩の疑い) を検知する (RFC 6749 §4.1.2)
        (1, "ALTER TABLE authorization_codes ADD COLUMN consumed_at TEXT"),
        // v2: リフレッシュトークンの発行元認可コード。認可コード再使用・RT リプレイ時に同一ファミリーをまとめて失効させる
        (2, "ALTER TABLE refresh_tokens ADD COLUMN source_code_hash TEXT")
    ];

    public static void Initialize(DbConnectionFactory factory)
    {
        ArgumentNullException.ThrowIfNull(factory);
        using var connection = factory.OpenConnection();
        connection.Execute(Schema);

        var applied = connection.Query<long>("SELECT version FROM schema_migrations").ToHashSet();
        foreach (var (version, sql) in Migrations)
        {
            if (applied.Contains(version))
            {
                continue;
            }

            using var transaction = connection.BeginTransaction();
            connection.Execute(sql, transaction: transaction);
            connection.Execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (@Version, @AppliedAt)",
                new { Version = version, AppliedAt = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture) },
                transaction);
            transaction.Commit();
        }
    }
}
