namespace TestClient;

using System.Buffers.Text;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

// クライアント認証方式ごとにトークン系エンドポイントへの要求を組み立てる。
//   client_secret_post  : client_id / client_secret をフォームに含める (既定)
//   client_secret_basic : Authorization: Basic ヘッダーで送る
//   private_key_jwt     : 秘密鍵で署名した client_assertion (RFC 7523 / OIDC Core §9) を送る
//   none                : 公開クライアント。client_id のみ
internal static class ClientAuthHelper
{
    public const string SecretPost = "client_secret_post";
    public const string SecretBasic = "client_secret_basic";
    public const string PrivateKeyJwt = "private_key_jwt";
    public const string None = "none";

    public const string InvalidMethodMessage = "--auth-method must be client_secret_post, client_secret_basic, private_key_jwt, or none.";

    public static readonly string[] Methods = [SecretPost, SecretBasic, PrivateKeyJwt, None];

    // AuthServer の DataSeeder が登録する test-jwt-client の公開鍵に対応する、開発用の秘密鍵 (テストフィクスチャ)。
    // 本番では各クライアントが鍵を生成して公開鍵 (JWKS) だけを登録し、秘密鍵はクライアントの外に出さない。
    public const string DevPrivateJwk =
        """{"kty":"EC","crv":"P-256","kid":"test-jwt-client-key-1","use":"sig","alg":"ES256","x":"fn5umSHzhOJPWsYiRUym3idqsL_pMRPjBF6inYrlpMc","y":"Rm1bMhzItJAwBUes0bYl089scqmxWnE1_hIximqboLk","d":"MZkSyMv8Q__95Azty5o10r5Ffr5nczogA-OOkrPZwj8"}""";

    public static string? Normalize(string? authMethod) => CommandOptionHelper.NormalizeChoice(authMethod, SecretPost, Methods);

    // form にクライアント認証情報を加えた POST 要求を作る。audience は private_key_jwt の aud (呼び出すエンドポイントの URL)。
    public static HttpRequestMessage CreateRequest(
        string endpoint, Dictionary<string, string> form, string clientId, string? clientSecret, string authMethod, string? clientKeyPath)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        switch (authMethod)
        {
            case SecretBasic:
                var credentials = $"{Uri.EscapeDataString(clientId)}:{Uri.EscapeDataString(clientSecret ?? String.Empty)}";
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials)));
                break;
            case PrivateKeyJwt:
                form["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
                form["client_assertion"] = CreateClientAssertion(clientId, endpoint, LoadPrivateJwk(clientKeyPath));
                break;
            case None:
                form["client_id"] = clientId;
                break;
            default:
                form["client_id"] = clientId;
                form["client_secret"] = clientSecret ?? String.Empty;
                break;
        }

        request.Content = new FormUrlEncodedContent(form);
        return request;
    }

    public static string LoadPrivateJwk(string? path) =>
        String.IsNullOrEmpty(path) ? DevPrivateJwk : File.ReadAllText(path);

    // RFC 7523 §3 のクライアントアサーション: iss = sub = client_id、aud = エンドポイント URL、exp は短命 (60 秒)、jti は一回限り。
    public static string CreateClientAssertion(string clientId, string audience, string privateJwkJson)
    {
        using var doc = JsonDocument.Parse(privateJwkJson);
        var jwk = doc.RootElement;
        var kty = jwk.GetProperty("kty").GetString();
        var kid = jwk.TryGetProperty("kid", out var k) ? k.GetString() : null;

        var now = DateTimeOffset.UtcNow;
        var payload = new Dictionary<string, object>
        {
            ["iss"] = clientId,
            ["sub"] = clientId,
            ["aud"] = audience,
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = now.AddSeconds(60).ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N")
        };

        var alg = kty switch
        {
            "EC" => "ES256",
            "RSA" => "RS256",
            _ => throw new InvalidOperationException($"Unsupported key type '{kty}' in private JWK.")
        };

        var signingInput = CreateSigningInput(alg, kid, payload);
        var data = Encoding.ASCII.GetBytes(signingInput);
        byte[] signature;
        if (alg == "ES256")
        {
            using var ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = Decode(jwk, "x"), Y = Decode(jwk, "y") },
                D = Decode(jwk, "d")
            });
            signature = ecdsa.SignData(data, HashAlgorithmName.SHA256);
        }
        else
        {
            using var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters
            {
                Modulus = Decode(jwk, "n"),
                Exponent = Decode(jwk, "e"),
                D = Decode(jwk, "d"),
                P = Decode(jwk, "p"),
                Q = Decode(jwk, "q"),
                DP = Decode(jwk, "dp"),
                DQ = Decode(jwk, "dq"),
                InverseQ = Decode(jwk, "qi")
            });
            signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        return signingInput + "." + Base64Url.EncodeToString(signature);
    }

    // P-256 鍵ペアを生成し、登録用の公開 JWKS と秘密 JWK (JSON) を返す。
    public static (string PublicJwks, string PrivateJwk) GenerateKeyPair(string kid)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var p = ecdsa.ExportParameters(true);
        var x = Base64Url.EncodeToString(p.Q.X);
        var y = Base64Url.EncodeToString(p.Q.Y);
        var d = Base64Url.EncodeToString(p.D);
        var publicJwks = JsonSerializer.Serialize(new { keys = new[] { new { kty = "EC", crv = "P-256", kid, use = "sig", alg = "ES256", x, y } } });
        var privateJwk = JsonSerializer.Serialize(new { kty = "EC", crv = "P-256", kid, use = "sig", alg = "ES256", x, y, d });
        return (publicJwks, privateJwk);
    }

    // JWT の署名対象 (base64url のヘッダー + "." + base64url のペイロード)
    private static string CreateSigningInput(string alg, string? kid, Dictionary<string, object> payload)
    {
        var header = new Dictionary<string, object> { ["alg"] = alg, ["typ"] = "JWT" };
        if (!String.IsNullOrEmpty(kid))
        {
            header["kid"] = kid;
        }

        return Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(header)) + "." +
               Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(payload));
    }

    private static byte[] Decode(JsonElement jwk, string name) =>
        Base64Url.DecodeFromChars(jwk.GetProperty(name).GetString() ?? String.Empty);
}
