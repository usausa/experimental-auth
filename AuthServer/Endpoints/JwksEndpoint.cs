namespace AuthServer.Endpoints;

using System.Security.Cryptography;
using AuthServer.Services;
using Microsoft.IdentityModel.Tokens;

public static class JwksEndpoint
{
    public static void MapJwksEndpoint(this WebApplication app)
    {
        app.MapGet("/.well-known/jwks.json", HandleJwks);
    }

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
