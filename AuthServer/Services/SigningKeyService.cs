namespace AuthServer.Services;

using System.Globalization;
using System.Security.Cryptography;

using AuthServer.Database;
using AuthServer.Models;

using Dapper;

using Microsoft.IdentityModel.Tokens;

// RSA 署名鍵を SQLite に永続化し、JWT 署名と JWKS 公開で利用する
public sealed class SigningKeyService : IDisposable
{
    private readonly DbConnectionFactory dbFactory;
    private readonly Lock gate = new();
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

    public IReadOnlyList<SigningKey> GetAllActiveKeys()
    {
        using var connection = dbFactory.OpenConnection();
        return connection.Query<SigningKey>("""
            SELECT kid AS Kid, algorithm AS Algorithm,
                   private_key_pem AS PrivateKeyPem, public_key_pem AS PublicKeyPem,
                   is_active AS IsActive, created_at AS CreatedAt, expires_at AS ExpiresAt
            FROM signing_keys WHERE is_active = 1
            """).ToList();
    }

    private void EnsureKeyExists()
    {
        using var connection = dbFactory.OpenConnection();
        var count = connection.ExecuteScalar<long>("SELECT COUNT(*) FROM signing_keys WHERE is_active = 1");
        if (count > 0)
        {
            return;
        }

        using var rsa = RSA.Create(2048);
        var kid = Guid.NewGuid().ToString("N")[..16];
        var privatePem = rsa.ExportRSAPrivateKeyPem();
        var publicPem = rsa.ExportRSAPublicKeyPem();
        var now = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);

        connection.Execute("""
            INSERT INTO signing_keys (kid, algorithm, private_key_pem, public_key_pem, is_active, created_at)
            VALUES (@Kid, 'RS256', @PrivateKeyPem, @PublicKeyPem, 1, @CreatedAt)
            """,
            new { Kid = kid, PrivateKeyPem = privatePem, PublicKeyPem = publicPem, CreatedAt = now });
    }

    private void LoadActiveKey()
    {
        using var connection = dbFactory.OpenConnection();
        var row = connection.QueryFirstOrDefault<SigningKey>("""
            SELECT kid AS Kid, algorithm AS Algorithm,
                   private_key_pem AS PrivateKeyPem, public_key_pem AS PublicKeyPem,
                   is_active AS IsActive, created_at AS CreatedAt, expires_at AS ExpiresAt
            FROM signing_keys WHERE is_active = 1 ORDER BY created_at DESC LIMIT 1
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
