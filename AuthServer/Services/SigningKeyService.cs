namespace AuthServer.Services;

using System.Data;
using System.Globalization;
using System.Security.Cryptography;

using AuthServer.Database;
using AuthServer.Models;

using Dapper;

using Microsoft.IdentityModel.Tokens;

// RSA 署名鍵を SQLite に永続化し、JWT 署名と JWKS 公開で利用する。
// 鍵の状態は 3 つ: 現用 (is_active=1, expires_at NULL) / 猶予期間 (is_active=1, expires_at あり) / 退役 (is_active=0)。
// ローテーションすると現用鍵は猶予期間へ移り、有効期限まで JWKS に公開され続けるため、旧鍵で署名済みのトークンも検証できる。
public sealed class SigningKeyService : IDisposable
{
    private const string SelectColumns = """
        kid AS Kid, algorithm AS Algorithm,
        private_key_pem AS PrivateKeyPem, public_key_pem AS PublicKeyPem,
        is_active AS IsActive, created_at AS CreatedAt, expires_at AS ExpiresAt
        """;

    private readonly DbConnectionFactory dbFactory;
    private readonly Lock gate = new();
    private readonly List<RSA> retiredRsa = [];
    private RSA? signingRsa;
    private RsaSecurityKey? cachedKey;
    private string? cachedKid;

    public SigningKeyService(DbConnectionFactory dbFactory)
    {
        this.dbFactory = dbFactory;
        EnsureKeyExists();
    }

    public void Dispose()
    {
        lock (gate)
        {
            signingRsa?.Dispose();
            signingRsa = null;
            foreach (var rsa in retiredRsa)
            {
                rsa.Dispose();
            }

            retiredRsa.Clear();
            cachedKey = null;
            cachedKid = null;
        }
    }

    // ReSharper disable once UnusedTupleComponentInReturnValue
    public (RsaSecurityKey Key, string Kid) GetActiveKey()
    {
        lock (gate)
        {
            if ((cachedKey is null) || (cachedKid is null))
            {
                LoadActiveKey();
            }
            return (cachedKey!, cachedKid!);
        }
    }

    // 検証に使える鍵 (現用 + 猶予期間中) を返す。JWKS と AuthServer 内のトークン検証で使用する。
    public IReadOnlyList<SigningKey> GetAllActiveKeys()
    {
        using var connection = dbFactory.OpenConnection();
        return connection.Query<SigningKey>($"""
            SELECT {SelectColumns}
            FROM signing_keys
            WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > @Now)
            ORDER BY (expires_at IS NULL) DESC, created_at DESC
            """, new { Now = NowString() }).ToList();
    }

    // 退役した鍵を含むすべての鍵を返す (管理画面用)。
    public IReadOnlyList<SigningKey> GetAllKeys()
    {
        using var connection = dbFactory.OpenConnection();
        return connection.Query<SigningKey>($"SELECT {SelectColumns} FROM signing_keys ORDER BY created_at DESC").ToList();
    }

    // 現用鍵の生成時刻。自動ローテーションの判定に使う。
    public DateTime? GetCurrentKeyCreatedAt()
    {
        using var connection = dbFactory.OpenConnection();
        var value = connection.ExecuteScalar<string?>(
            "SELECT MAX(created_at) FROM signing_keys WHERE is_active = 1 AND expires_at IS NULL");
        return value is null
            ? null
            : DateTime.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
    }

    // 新しい署名鍵を生成して現用にし、それまでの現用鍵に猶予期間つきの有効期限を設定する。新鍵の kid を返す。
    public string RotateKey(TimeSpan gracePeriod)
    {
        lock (gate)
        {
            using var connection = dbFactory.OpenConnection();
            using var transaction = connection.BeginTransaction();
            var now = DateTime.UtcNow;

            connection.Execute("""
                UPDATE signing_keys SET expires_at = @ExpiresAt
                WHERE is_active = 1 AND expires_at IS NULL
                """,
                new { ExpiresAt = now.Add(gracePeriod).ToString("o", CultureInfo.InvariantCulture) },
                transaction);

            var kid = InsertNewKey(connection, transaction, now);
            transaction.Commit();

            // キャッシュを破棄し、次回 GetActiveKey で新鍵を読み込む。
            // 旧 RSA は別スレッドが署名処理中の可能性があるため即時 Dispose せず、サービス破棄時にまとめて解放する。
            if (signingRsa is not null)
            {
                retiredRsa.Add(signingRsa);
            }

            signingRsa = null;
            cachedKey = null;
            cachedKid = null;
            return kid;
        }
    }

    // 猶予期間を過ぎた鍵を退役 (is_active=0) させる。退役した件数を返す。現用鍵 (expires_at NULL) は対象外。
    public int RetireExpiredKeys(DateTime now)
    {
        using var connection = dbFactory.OpenConnection();
        return connection.Execute("""
            UPDATE signing_keys SET is_active = 0
            WHERE is_active = 1 AND expires_at IS NOT NULL AND expires_at <= @Now
            """, new { Now = now.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture) });
    }

    private static string NowString() => DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);

    private static string InsertNewKey(IDbConnection connection, IDbTransaction? transaction, DateTime now)
    {
        using var rsa = RSA.Create(2048);
        var kid = Guid.NewGuid().ToString("N")[..16];
        connection.Execute("""
            INSERT INTO signing_keys (kid, algorithm, private_key_pem, public_key_pem, is_active, created_at)
            VALUES (@Kid, 'RS256', @PrivateKeyPem, @PublicKeyPem, 1, @CreatedAt)
            """,
            new
            {
                Kid = kid,
                PrivateKeyPem = rsa.ExportRSAPrivateKeyPem(),
                PublicKeyPem = rsa.ExportRSAPublicKeyPem(),
                CreatedAt = now.ToString("o", CultureInfo.InvariantCulture)
            },
            transaction);
        return kid;
    }

    private void EnsureKeyExists()
    {
        using var connection = dbFactory.OpenConnection();
        var count = connection.ExecuteScalar<long>(
            "SELECT COUNT(*) FROM signing_keys WHERE is_active = 1 AND expires_at IS NULL");
        if (count > 0)
        {
            return;
        }

        InsertNewKey(connection, null, DateTime.UtcNow);
    }

    private void LoadActiveKey()
    {
        using var connection = dbFactory.OpenConnection();
        var row = connection.QueryFirstOrDefault<SigningKey>($"""
            SELECT {SelectColumns}
            FROM signing_keys
            WHERE is_active = 1
            ORDER BY (expires_at IS NULL) DESC, created_at DESC
            LIMIT 1
            """) ?? throw new InvalidOperationException("No active signing key.");

        // RsaSecurityKey は RSA をコピーせず参照として保持するため、ローカルの using で破棄してはいけない。
        // using を付けるとキャッシュ済みの鍵が破棄済みインスタンスを包み、署名時に
        // ObjectDisposedException となってトークン発行が必ず失敗する。
        // 所有権をフィールドに持たせ、Dispose でまとめて破棄する。
        // (ExportParameters で値をコピーしてから破棄している JwksEndpoint とは扱いが異なる)
        var rsa = RSA.Create();
        rsa.ImportFromPem(row.PrivateKeyPem);

        signingRsa?.Dispose();
        signingRsa = rsa;
        cachedKey = new RsaSecurityKey(rsa) { KeyId = row.Kid };
        cachedKid = row.Kid;
    }
}
