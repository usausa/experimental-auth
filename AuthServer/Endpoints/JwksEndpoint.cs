namespace AuthServer.Endpoints;

using System.Globalization;
using System.Security.Cryptography;

using AuthServer.Models;
using AuthServer.Services;

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

public static class JwksEndpoint
{
    public static void MapJwksEndpoint(this WebApplication app)
    {
        app.MapGet("/.well-known/jwks.json", HandleJwks)
            .WithTags("Discovery")
            .WithSummary("JSON Web Key Set (JWKS) の取得")
            .WithDescription("アクセストークンの署名検証に使用する公開鍵一覧を返します(RFC 7517)。予約中の鍵とローテーション後の旧鍵 (猶予期間中) も含まれます。")
            .Produces<object>(StatusCodes.Status200OK, "application/json")
            .AllowAnonymous();
    }

    //--------------------------------------------------------------------------------
    // JSON Web Key Set (JWKS) エンドポイント
    // GET /.well-known/jwks.json
    // リソースサーバーがアクセストークンの署名検証に使用する公開鍵一覧を返す標準エンドポイント(RFC 7517)。
    // 現用鍵に加えて、事前公開中の予約鍵 (署名にはまだ使っていない) と猶予期間中の旧鍵を返す。
    // RSA は n/e、EC は crv/x/y (RFC 7518 §6)。EC 座標は曲線のバイト長 (P-256 は 32) に左ゼロ埋めする。
    // Cache-Control の max-age は鍵の事前公開期間・猶予期間より短くし、切り替え前にキャッシュが更新されるようにする。
    //--------------------------------------------------------------------------------

    private static IResult HandleJwks(HttpContext context, SigningKeyService keyService, IOptions<AuthServerOptions> options)
    {
        var keys = new List<object>();
        foreach (var sk in keyService.GetAllActiveKeys())
        {
            keys.Add(sk.Algorithm == SigningKeyService.Es256 ? CreateEcJwk(sk) : CreateRsaJwk(sk));
        }

        context.Response.Headers.CacheControl =
            "public, max-age=" + options.Value.JwksCacheMaxAgeSeconds.ToString(CultureInfo.InvariantCulture);
        return Results.Json(new { keys });
    }

    private static object CreateRsaJwk(SigningKey sk)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(sk.PublicKeyPem);
        var parameters = rsa.ExportParameters(includePrivateParameters: false);
        return new
        {
            kty = "RSA",
            use = "sig",
            alg = sk.Algorithm,
            kid = sk.Kid,
            n = Base64UrlEncoder.Encode(parameters.Modulus),
            e = Base64UrlEncoder.Encode(parameters.Exponent)
        };
    }

    private static object CreateEcJwk(SigningKey sk)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(sk.PublicKeyPem);
        var parameters = ecdsa.ExportParameters(includePrivateParameters: false);
        return new
        {
            kty = "EC",
            use = "sig",
            alg = sk.Algorithm,
            kid = sk.Kid,
            crv = "P-256",
            x = Base64UrlEncoder.Encode(PadLeft(parameters.Q.X!, 32)),
            y = Base64UrlEncoder.Encode(PadLeft(parameters.Q.Y!, 32))
        };
    }

    // ExportParameters は先頭のゼロを省くことがあるため、JWK では曲線のバイト長に揃える (RFC 7518 §6.2.1.2)
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
}
