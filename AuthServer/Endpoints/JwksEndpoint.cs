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
            .WithDescription("アクセストークンの署名検証に使用する公開鍵一覧を返します(RFC 7517)。ローテーション後の旧鍵も猶予期間中は含まれます。")
            .Produces<object>(StatusCodes.Status200OK, "application/json")
            .AllowAnonymous();
    }

    //--------------------------------------------------------------------------------
    // JSON Web Key Set (JWKS) エンドポイント
    // GET /.well-known/jwks.json
    // リソースサーバーがアクセストークンの署名検証に使用する公開鍵一覧を返す
    // 標準エンドポイント(RFC 7517)。現用鍵と猶予期間中の旧鍵を RSA 公開鍵形式で返す。
    // Cache-Control の max-age は鍵ローテーションの猶予期間より短くし、旧鍵の退役前にキャッシュが更新されるようにする。
    //--------------------------------------------------------------------------------

    private static IResult HandleJwks(HttpContext context, SigningKeyService keyService, IOptions<AuthServerOptions> options)
    {
        var keys = new List<object>();
        foreach (var sk in keyService.GetAllActiveKeys())
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(sk.PublicKeyPem);
            var parameters = rsa.ExportParameters(includePrivateParameters: false);
            keys.Add(new
            {
                kty = "RSA",
                use = "sig",
                alg = sk.Algorithm,
                kid = sk.Kid,
                n = Base64UrlEncoder.Encode(parameters.Modulus),
                e = Base64UrlEncoder.Encode(parameters.Exponent)
            });
        }

        context.Response.Headers.CacheControl =
            "public, max-age=" + options.Value.JwksCacheMaxAgeSeconds.ToString(CultureInfo.InvariantCulture);
        return Results.Json(new { keys });
    }
}
