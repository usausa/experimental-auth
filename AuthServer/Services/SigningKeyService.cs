namespace AuthServer.Services;

using System.Data;
using System.Globalization;
using System.Security.Cryptography;

using AuthServer.Database;
using AuthServer.Models;

using Dapper;

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

// RSA (RS256) / ECDSA (ES256) の署名鍵を SQLite に永続化し、JWT 署名と JWKS 公開で利用する。
// 鍵の状態は 4 つ:
//   予約 (pending) : is_active=1, expires_at NULL, activates_at > now  … JWKS に公開済みだが署名には未使用 (事前公開)
//   現用 (current) : is_active=1, expires_at NULL, activates_at NULL または過去
//   猶予 (grace)   : is_active=1, expires_at あり … 有効期限まで JWKS に残り、旧鍵で署名済みのトークンを検証できる
//   退役 (retired) : is_active=0
// 予約鍵の有効化時刻を過ぎると、それまでの現用鍵に猶予期限を付けて世代交代する (2 段階ローテーション)。
public sealed class SigningKeyService : IDisposable
{
    public const string Rs256 = "RS256";
    public const string Es256 = "ES256";

    private const string SelectColumns = """
        kid AS Kid, algorithm AS Algorithm,
        private_key_pem AS PrivateKeyPem, public_key_pem AS PublicKeyPem,
        is_active AS IsActive, created_at AS CreatedAt, expires_at AS ExpiresAt, activates_at AS ActivatesAt
        """;

    // 「現用になれる鍵」= 有効・猶予期限なし・有効化時刻が未来でない
    private const string CurrentEligible = "is_active = 1 AND expires_at IS NULL AND (activates_at IS NULL OR activates_at <= @Now)";

    private readonly DbConnectionFactory dbFactory;
    private readonly AuthServerOptions options;
    private readonly Lock gate = new();
    private readonly List<AsymmetricAlgorithm> retiredAlgorithms = [];
    private AsymmetricAlgorithm? signingAlgorithm;
    private ActiveSigningKey? cachedKey;
    private DateTime? pendingActivatesAt;
    private string? validationKeySetId;
    private IReadOnlyList<SecurityKey> validationKeys = [];

    public SigningKeyService(DbConnectionFactory dbFactory, IOptions<AuthServerOptions> options)
    {
        this.dbFactory = dbFactory;
        this.options = options.Value;
        EnsureKeyExists();
    }

    public void Dispose()
    {
        lock (gate)
        {
            signingAlgorithm?.Dispose();
            signingAlgorithm = null;
            foreach (var algorithm in retiredAlgorithms)
            {
                algorithm.Dispose();
            }

            retiredAlgorithms.Clear();
            cachedKey = null;
        }
    }

    // 署名に使う現用鍵。予約鍵の有効化時刻を過ぎていれば世代交代してから返す。
    public ActiveSigningKey GetActiveKey()
    {
        lock (gate)
        {
            var now = DateTime.UtcNow;
            if ((cachedKey is null) || (pendingActivatesAt <= now))
            {
                LoadActiveKey(now);
            }

            return cachedKey!;
        }
    }

    // トークン検証に使う公開鍵 (現用 + 予約 + 猶予)。kid の集合が変わったときだけ再構築する。
    public IReadOnlyList<SecurityKey> GetValidationKeys()
    {
        var keys = GetAllActiveKeys();
        var setId = String.Join(',', keys.Select(k => k.Kid));
        lock (gate)
        {
            if (!String.Equals(setId, validationKeySetId, StringComparison.Ordinal))
            {
                validationKeys = keys.Select(CreatePublicSecurityKey).ToList();
                validationKeySetId = setId;
            }

            return validationKeys;
        }
    }

    // 公開対象の鍵 (現用 + 予約 + 猶予期間中)。JWKS と検証で使用する。
    public IReadOnlyList<SigningKey> GetAllActiveKeys()
    {
        using var connection = dbFactory.OpenConnection();
        return connection.Query<SigningKey>($"""
            SELECT {SelectColumns}
            FROM signing_keys
            WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > @Now)
            ORDER BY (expires_at IS NULL) DESC, created_at DESC
            """, new { Now = Format(DateTime.UtcNow) }).ToList();
    }

    // 退役した鍵を含むすべての鍵 (管理画面用)。
    public IReadOnlyList<SigningKey> GetAllKeys()
    {
        using var connection = dbFactory.OpenConnection();
        return connection.Query<SigningKey>($"SELECT {SelectColumns} FROM signing_keys ORDER BY created_at DESC").ToList();
    }

    // 現用鍵の生成時刻 (自動ローテーションの判定用)。
    public DateTime? GetCurrentKeyCreatedAt()
    {
        using var connection = dbFactory.OpenConnection();
        var value = connection.ExecuteScalar<string?>(
            $"SELECT MAX(created_at) FROM signing_keys WHERE {CurrentEligible}", new { Now = Format(DateTime.UtcNow) });
        return value is null ? null : ParseUtc(value);
    }

    public bool HasPendingKey()
    {
        using var connection = dbFactory.OpenConnection();
        return connection.ExecuteScalar<long>(
            "SELECT COUNT(*) FROM signing_keys WHERE is_active = 1 AND expires_at IS NULL AND activates_at > @Now",
            new { Now = Format(DateTime.UtcNow) }) > 0;
    }

    // 即時ローテーション: 新鍵を生成してすぐ現用にし、それまでの現用鍵に猶予期限を付ける。新鍵の kid を返す。
    // ResourceServer は次に未知の kid を受けた要求を 1 回失敗させてから JWKS を再取得するため、無停止で切り替えたい場合は ScheduleRotation を使う。
    public string RotateKey(string algorithm)
    {
        lock (gate)
        {
            using var connection = dbFactory.OpenConnection();
            using var transaction = connection.BeginTransaction();
            var now = DateTime.UtcNow;

            connection.Execute($"UPDATE signing_keys SET expires_at = @GraceEnd WHERE {CurrentEligible}",
                new { GraceEnd = Format(now.AddDays(options.SigningKeyGraceDays)), Now = Format(now) }, transaction);
            var kid = InsertNewKey(connection, transaction, algorithm, now, activatesAt: null);
            transaction.Commit();

            InvalidateCache();
            return kid;
        }
    }

    // 2 段階ローテーション: 新鍵を予約 (JWKS に公開、署名には未使用) し、SigningKeyPrePublishSeconds 経過後に現用へ昇格させる。
    // 既に予約鍵があれば新たに作らず、その kid を返す。
    public string ScheduleRotation(string algorithm)
    {
        lock (gate)
        {
            using var connection = dbFactory.OpenConnection();
            var now = DateTime.UtcNow;
            var existing = connection.ExecuteScalar<string?>(
                "SELECT kid FROM signing_keys WHERE is_active = 1 AND expires_at IS NULL AND activates_at > @Now ORDER BY activates_at LIMIT 1",
                new { Now = Format(now) });
            if (existing is not null)
            {
                return existing;
            }

            var activatesAt = now.AddSeconds(options.SigningKeyPrePublishSeconds);
            var kid = InsertNewKey(connection, null, algorithm, now, activatesAt);
            pendingActivatesAt = activatesAt;
            return kid;
        }
    }

    // 有効化時刻を過ぎた予約鍵を現用へ昇格させる (それまでの現用鍵に猶予期限を付ける)。昇格が起きれば true。
    public bool PromoteDueKeys(DateTime now)
    {
        lock (gate)
        {
            using var connection = dbFactory.OpenConnection();
            var promoted = PromoteDueKeys(connection, null, now) > 0;
            if (promoted)
            {
                InvalidateCache();
            }

            return promoted;
        }
    }

    // 猶予期間を過ぎた鍵を退役 (is_active=0) させる。退役した件数を返す。
    public int RetireExpiredKeys(DateTime now)
    {
        using var connection = dbFactory.OpenConnection();
        return connection.Execute("""
            UPDATE signing_keys SET is_active = 0
            WHERE is_active = 1 AND expires_at IS NOT NULL AND expires_at <= @Now
            """, new { Now = Format(now) });
    }

    // 鍵レコードから検証用の公開鍵を作る。RSA はパラメーターを、EC は JWK 座標をコピーした不変オブジェクトにし、
    // 元の鍵オブジェクトはその場で破棄する (署名用の現用鍵とは異なり、所有権を持ち回らない)。
    public static SecurityKey CreatePublicSecurityKey(SigningKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        switch (key.Algorithm)
        {
            case Rs256:
            {
                using var rsa = RSA.Create();
                rsa.ImportFromPem(key.PublicKeyPem);
                return new RsaSecurityKey(rsa.ExportParameters(false)) { KeyId = key.Kid };
            }

            case Es256:
            {
                using var ecdsa = ECDsa.Create();
                ecdsa.ImportFromPem(key.PublicKeyPem);
                var parameters = ecdsa.ExportParameters(false);
                return new JsonWebKey
                {
                    Kty = "EC",
                    Crv = "P-256",
                    X = Base64UrlEncoder.Encode(PadLeft(parameters.Q.X!, 32)),
                    Y = Base64UrlEncoder.Encode(PadLeft(parameters.Q.Y!, 32)),
                    KeyId = key.Kid,
                    Use = "sig",
                    Alg = key.Algorithm
                };
            }

            default:
                throw new InvalidOperationException($"Unsupported signing algorithm '{key.Algorithm}'.");
        }
    }

    public static string ToSigningAlgorithm(string algorithm) => algorithm switch
    {
        Rs256 => SecurityAlgorithms.RsaSha256,
        Es256 => SecurityAlgorithms.EcdsaSha256,
        _ => throw new ArgumentException($"Unsupported signing algorithm '{algorithm}'.", nameof(algorithm))
    };

    private static int PromoteDueKeys(IDbConnection connection, IDbTransaction? transaction, DateTime now)
    {
        // 現用になれる鍵が複数あれば、最新以外に猶予期限を付ける (= 予約鍵の有効化による世代交代)
        var graceEnd = Format(now.AddDays(7));
        return connection.Execute($"""
            UPDATE signing_keys SET expires_at = @GraceEnd
            WHERE {CurrentEligible}
              AND created_at < (SELECT MAX(created_at) FROM signing_keys WHERE {CurrentEligible})
            """, new { GraceEnd = graceEnd, Now = Format(now) }, transaction);
    }

    private static (string PrivatePem, string PublicPem) CreateKeyMaterial(string algorithm)
    {
        switch (algorithm)
        {
            case Rs256:
            {
                using var rsa = RSA.Create(2048);
                return (rsa.ExportRSAPrivateKeyPem(), rsa.ExportRSAPublicKeyPem());
            }

            case Es256:
            {
                using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                return (ecdsa.ExportECPrivateKeyPem(), ecdsa.ExportSubjectPublicKeyInfoPem());
            }

            default:
                throw new ArgumentException($"Unsupported signing algorithm '{algorithm}'.", nameof(algorithm));
        }
    }

    private static string InsertNewKey(IDbConnection connection, IDbTransaction? transaction, string algorithm, DateTime now, DateTime? activatesAt)
    {
        var (privatePem, publicPem) = CreateKeyMaterial(algorithm);
        var kid = Guid.NewGuid().ToString("N")[..16];
        connection.Execute("""
            INSERT INTO signing_keys (kid, algorithm, private_key_pem, public_key_pem, is_active, created_at, activates_at)
            VALUES (@Kid, @Algorithm, @PrivateKeyPem, @PublicKeyPem, 1, @CreatedAt, @ActivatesAt)
            """,
            new
            {
                Kid = kid,
                Algorithm = algorithm,
                PrivateKeyPem = privatePem,
                PublicKeyPem = publicPem,
                CreatedAt = Format(now),
                ActivatesAt = activatesAt is null ? null : Format(activatesAt.Value)
            },
            transaction);
        return kid;
    }

    // ExportParameters は先頭のゼロを省くことがあるため、JWK の座標は曲線のバイト長に揃える (RFC 7518 §6.2.1.2)
    private static byte[] PadLeft(byte[] value, int length)
    {
        if (value.Length >= length)
        {
            return value;
        }

        var padded = new byte[length];
        value.CopyTo(padded, length - value.Length);
        return padded;
    }

    private static string Format(DateTime value) => value.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);

    private static DateTime ParseUtc(string value) => DateTime.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

    private void EnsureKeyExists()
    {
        using var connection = dbFactory.OpenConnection();
        var count = connection.ExecuteScalar<long>(
            $"SELECT COUNT(*) FROM signing_keys WHERE {CurrentEligible}", new { Now = Format(DateTime.UtcNow) });
        if (count > 0)
        {
            return;
        }

        InsertNewKey(connection, null, options.SigningKeyAlgorithm, DateTime.UtcNow, activatesAt: null);
    }

    // キャッシュを破棄し、次回 GetActiveKey で鍵を読み直す。
    // 旧アルゴリズムは別スレッドが署名処理中の可能性があるため即時 Dispose せず、サービス破棄時にまとめて解放する。
    private void InvalidateCache()
    {
        if (signingAlgorithm is not null)
        {
            retiredAlgorithms.Add(signingAlgorithm);
        }

        signingAlgorithm = null;
        cachedKey = null;
        pendingActivatesAt = null;
    }

    private void LoadActiveKey(DateTime now)
    {
        using var connection = dbFactory.OpenConnection();
        var promoted = PromoteDueKeys(connection, null, now);
        if ((promoted > 0) && (signingAlgorithm is not null))
        {
            retiredAlgorithms.Add(signingAlgorithm);
            signingAlgorithm = null;
        }

        var row = connection.QueryFirstOrDefault<SigningKey>($"""
            SELECT {SelectColumns}
            FROM signing_keys
            WHERE {CurrentEligible}
            ORDER BY created_at DESC
            LIMIT 1
            """, new { Now = Format(now) }) ?? throw new InvalidOperationException("No active signing key.");

        var nextActivation = connection.ExecuteScalar<string?>(
            "SELECT MIN(activates_at) FROM signing_keys WHERE is_active = 1 AND expires_at IS NULL AND activates_at > @Now",
            new { Now = Format(now) });
        pendingActivatesAt = nextActivation is null ? null : ParseUtc(nextActivation);

        // SecurityKey は鍵オブジェクトをコピーせず参照として保持するため、ローカルの using で破棄してはいけない。
        // 破棄するとキャッシュ済みの鍵が破棄済みインスタンスを包み、署名時に ObjectDisposedException となる。
        // 所有権をフィールドに持たせ、Dispose でまとめて破棄する。
        SecurityKey securityKey;
        switch (row.Algorithm)
        {
            case Rs256:
            {
                var rsa = RSA.Create();
                rsa.ImportFromPem(row.PrivateKeyPem);
                signingAlgorithm = rsa;
                securityKey = new RsaSecurityKey(rsa) { KeyId = row.Kid };
                break;
            }

            case Es256:
            {
                var ecdsa = ECDsa.Create();
                ecdsa.ImportFromPem(row.PrivateKeyPem);
                signingAlgorithm = ecdsa;
                securityKey = new ECDsaSecurityKey(ecdsa) { KeyId = row.Kid };
                break;
            }

            default:
                throw new InvalidOperationException($"Unsupported signing algorithm '{row.Algorithm}'.");
        }

        cachedKey = new ActiveSigningKey(securityKey, ToSigningAlgorithm(row.Algorithm));
    }
}

// 署名に使う鍵。SigningAlgorithm は IdentityModel の SecurityAlgorithms 定数 (RS256 → RsaSha256, ES256 → EcdsaSha256)。kid は Key.KeyId が持つ。
public sealed record ActiveSigningKey(SecurityKey Key, string SigningAlgorithm);
