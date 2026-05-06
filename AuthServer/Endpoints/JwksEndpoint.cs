namespace AuthServer.Endpoints;

using System.Security.Cryptography;

using AuthServer.Services;

using Microsoft.IdentityModel.Tokens;

public static class JwksEndpoint
{
    public static void MapJwksEndpoint(this WebApplication app)
    {
        app.MapGet("/.well-known/jwks.json", HandleJwks)
            .WithTags("Discovery")
            .WithSummary("JSON Web Key Set (JWKS) の取得")
            .WithDescription("アクセストークンの署名検証に使用する公開鍵一覧を返します(RFC 7517)。")
            .Produces<object>(StatusCodes.Status200OK, "application/json")
            .AllowAnonymous();
    }

    //--------------------------------------------------------------------------------
    // JSON Web Key Set (JWKS) エンドポイント
    // GET /.well-known/jwks.json
    // リソースサーバーがアクセストークンの署名検証に使用する公開鍵一覧を返す
    // 標準エンドポイント(RFC 7517)。現在有効なすべての署名鍵を RSA 公開鍵形式で返す。
    //--------------------------------------------------------------------------------

    private static IResult HandleJwks(SigningKeyService keyService)
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
                n = Base64UrlEncoder.Encode(parameters.Modulus!),
                e = Base64UrlEncoder.Encode(parameters.Exponent!)
            });
        }
        return Results.Json(new { keys });
    }
}
