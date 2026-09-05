namespace AuthServer.Services;

using System.Security.Claims;

using AuthServer.Models;

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

public sealed class TokenService(SigningKeyService keyService, IOptions<AuthServerOptions> options)
{
    private readonly AuthServerOptions options = options.Value;

    public AccessTokenResult IssueClientCredentialsToken(string clientId, string scopes, string audience)
    {
        var (key, _) = keyService.GetActiveKey();
        var now = DateTime.UtcNow;
        var expires = now.AddSeconds(options.AccessTokenLifetimeSeconds);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, clientId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new("client_id", clientId),
            new("scope", scopes)
        };

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = options.Issuer,
            Audience = audience,
            IssuedAt = now,
            NotBefore = now,
            Expires = expires,
            Subject = new ClaimsIdentity(claims),
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256),
            TokenType = "at+jwt"
        };

        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        var token = handler.CreateToken(descriptor);
        return new AccessTokenResult(token, options.AccessTokenLifetimeSeconds, scopes);
    }

    // Authorization Code Flow 用のアクセストークンを発行する。
    public AccessTokenResult IssueAuthorizationCodeToken(string clientId, string userId, string username, string scopes, string audience)
    {
        var (key, _) = keyService.GetActiveKey();
        var now = DateTime.UtcNow;
        var expires = now.AddSeconds(options.AccessTokenLifetimeSeconds);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new("client_id", clientId),
            new("username", username),
            new("scope", scopes)
        };

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = options.Issuer,
            Audience = audience,
            IssuedAt = now,
            NotBefore = now,
            Expires = expires,
            Subject = new ClaimsIdentity(claims),
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256),
            TokenType = "at+jwt"
        };

        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        var token = handler.CreateToken(descriptor);
        return new AccessTokenResult(token, options.AccessTokenLifetimeSeconds, scopes);
    }

    // OpenID Connect の ID Token を発行する。
    public string IssueIdToken(string clientId, string userId, User user, string? nonce, string[] grantedScopes)
    {
        var (key, _) = keyService.GetActiveKey();
        var now = DateTime.UtcNow;

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new("azp", clientId)
        };

        if (nonce is not null)
        {
            claims.Add(new Claim("nonce", nonce));
        }

        // profile スコープ
        if (Array.IndexOf(grantedScopes, "profile") >= 0)
        {
            if (user.Name is not null)
            {
                claims.Add(new Claim("name", user.Name));
            }
            if (user.GivenName is not null)
            {
                claims.Add(new Claim("given_name", user.GivenName));
            }
            if (user.FamilyName is not null)
            {
                claims.Add(new Claim("family_name", user.FamilyName));
            }
            claims.Add(new Claim("preferred_username", user.Username));
        }

        // email スコープ
        if (Array.IndexOf(grantedScopes, "email") >= 0)
        {
            if (user.Email is not null)
            {
                claims.Add(new Claim("email", user.Email));
            }
            claims.Add(new Claim("email_verified", user.EmailVerified ? "true" : "false"));
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = options.Issuer,
            Audience = clientId,
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddSeconds(options.AccessTokenLifetimeSeconds),
            Subject = new ClaimsIdentity(claims),
            // kid は SigningCredentials の RsaSecurityKey.KeyId から自動的にヘッダーへ付与される。
            // AdditionalHeaderClaims で kid を渡すと IDX14116 で発行に失敗するため指定しない。
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
        };

        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        return handler.CreateToken(descriptor);
    }
}

public sealed record AccessTokenResult(string AccessToken, int ExpiresInSeconds, string Scope);
