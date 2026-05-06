namespace AuthServer.Services;

using System.Security.Claims;

using AuthServer.Models;

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

public sealed class TokenService(SigningKeyService keyService, IOptions<AuthServerOptions> options)
{
    private readonly AuthServerOptions options = options.Value;

    public AccessTokenResult IssueClientCredentialsToken(string clientId, string scopes, string? audience = null)
    {
        var (key, _) = keyService.GetActiveKey();
        var now = DateTime.UtcNow;
        var expires = now.AddSeconds(options.AccessTokenLifetimeSeconds);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, clientId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new("client_id", clientId),
            new("scope", scopes ?? string.Empty)
        };

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = options.Issuer,
            Audience = audience ?? options.DefaultAudience,
            IssuedAt = now,
            NotBefore = now,
            Expires = expires,
            Subject = new ClaimsIdentity(claims),
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256),
            TokenType = "at+jwt"
        };

        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        var token = handler.CreateToken(descriptor);
        return new AccessTokenResult(token, options.AccessTokenLifetimeSeconds, scopes ?? string.Empty);
    }
}

public sealed record AccessTokenResult(string AccessToken, int ExpiresInSeconds, string Scope);
