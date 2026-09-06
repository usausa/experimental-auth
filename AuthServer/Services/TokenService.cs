namespace AuthServer.Services;

using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

using AuthServer.Models;

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

public sealed class TokenService(SigningKeyService keyService, IOptions<AuthServerOptions> options)
{
    // amr (Authentication Methods References)。方式 B はパスワード認証のみ
    private static readonly string[] PasswordAmr = ["pwd"];

    private readonly AuthServerOptions options = options.Value;

    public AccessTokenResult IssueClientCredentialsToken(string clientId, string scopes, IReadOnlyList<string> audiences)
    {
        var signingKey = keyService.GetActiveKey();
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
            IssuedAt = now,
            NotBefore = now,
            Expires = expires,
            Subject = new ClaimsIdentity(claims),
            SigningCredentials = new SigningCredentials(signingKey.Key, signingKey.SigningAlgorithm),
            TokenType = "at+jwt"
        };

        ApplyAudiences(descriptor, audiences);

        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        var token = handler.CreateToken(descriptor);
        return new AccessTokenResult(token, options.AccessTokenLifetimeSeconds, scopes);
    }

    // Authorization Code Flow 用のアクセストークンを発行する。
    public AccessTokenResult IssueAuthorizationCodeToken(string clientId, string userId, string username, string scopes, IReadOnlyList<string> audiences)
    {
        var signingKey = keyService.GetActiveKey();
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
            IssuedAt = now,
            NotBefore = now,
            Expires = expires,
            Subject = new ClaimsIdentity(claims),
            SigningCredentials = new SigningCredentials(signingKey.Key, signingKey.SigningAlgorithm),
            TokenType = "at+jwt"
        };

        ApplyAudiences(descriptor, audiences);

        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        var token = handler.CreateToken(descriptor);
        return new AccessTokenResult(token, options.AccessTokenLifetimeSeconds, scopes);
    }

    // OpenID Connect の ID Token を発行する。
    // authTime はユーザー認証時刻 (auth_time)、accessToken を渡すと at_hash (OIDC Core §3.1.3.6) を付与する。
    public string IssueIdToken(string clientId, string userId, User user, string? nonce, string[] grantedScopes, DateTime authTime, string? accessToken)
    {
        var signingKey = keyService.GetActiveKey();
        var now = DateTime.UtcNow;

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new("azp", clientId)
        };

        // 数値・真偽値・配列のクレームは ClaimsIdentity 経由だと文字列化されるため、
        // Claims ディクショナリで型を保ったまま JSON に出力する。
        var typedClaims = new Dictionary<string, object>
        {
            ["auth_time"] = new DateTimeOffset(authTime.ToUniversalTime()).ToUnixTimeSeconds(),
            ["amr"] = PasswordAmr
        };

        if (accessToken is not null)
        {
            typedClaims["at_hash"] = ComputeAtHash(accessToken);
        }

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
            typedClaims["email_verified"] = user.EmailVerified;
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = options.Issuer,
            Audience = clientId,
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddSeconds(options.IdTokenLifetimeSeconds),
            Subject = new ClaimsIdentity(claims),
            Claims = typedClaims,
            // kid は SigningCredentials の SecurityKey.KeyId から自動的にヘッダーへ付与される。
            // AdditionalHeaderClaims で kid を渡すと IDX14116 で発行に失敗するため指定しない。
            SigningCredentials = new SigningCredentials(signingKey.Key, signingKey.SigningAlgorithm)
        };

        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        return handler.CreateToken(descriptor);
    }

    // アクセストークン (JWT) を検証し、クレームを返す。署名・発行者・有効期限を検証する。
    // typ ヘッダーが at+jwt でないもの (ID Token など) はアクセストークンとして受け付けない。
    // 失効リストの照合は呼び出し側 (UserInfo / Introspection) で行う。
    public async Task<AccessTokenClaims?> ValidateAccessTokenAsync(string token)
    {
        var securityKeys = keyService.GetValidationKeys();

        var handler = new JsonWebTokenHandler();
        var parameters = new TokenValidationParameters
        {
            ValidIssuer = options.Issuer,
            IssuerSigningKeys = securityKeys,
            // aud はリソースサーバーごとに異なり、AuthServer 自身は検証対象を固定できないため検証しない
            #pragma warning disable CA5404
            ValidateAudience = false,
            #pragma warning restore CA5404
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30)
        };

        var result = await handler.ValidateTokenAsync(token, parameters);
        if (!result.IsValid || (result.SecurityToken is not JsonWebToken jwt))
        {
            return null;
        }

        if (!String.Equals(jwt.Typ, "at+jwt", StringComparison.Ordinal))
        {
            return null;
        }

        var identity = result.ClaimsIdentity;
        return new AccessTokenClaims(
            jwt.Id,
            identity.FindFirst("sub")?.Value ?? String.Empty,
            identity.FindFirst("client_id")?.Value ?? String.Empty,
            identity.FindFirst("scope")?.Value ?? String.Empty,
            identity.FindFirst("username")?.Value,
            jwt.Audiences.ToList(),
            jwt.IssuedAt,
            jwt.ValidFrom,
            jwt.ValidTo);
    }

    // RFC 8707: audience が 1 つなら aud は文字列、複数なら配列で出力する (RFC 7519 §4.1.3)。
    // 配列は Claims ディクショナリ経由で型を保って出力する。
    private static void ApplyAudiences(SecurityTokenDescriptor descriptor, IReadOnlyList<string> audiences)
    {
        if (audiences.Count == 1)
        {
            descriptor.Audience = audiences[0];
        }
        else
        {
            descriptor.Claims = new Dictionary<string, object> { ["aud"] = audiences.ToArray() };
        }
    }

    // at_hash: アクセストークンの ASCII 表現を alg 対応のハッシュ (RS256 / ES256 はいずれも SHA-256) にかけ、
    // 左半分 (128bit) を base64url 化した値 (OIDC Core §3.1.3.6)。
    private static string ComputeAtHash(string accessToken)
    {
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(accessToken));
        return Base64UrlEncoder.Encode(hash, 0, hash.Length / 2);
    }
}

public sealed record AccessTokenResult(string AccessToken, int ExpiresInSeconds, string Scope);

public sealed record AccessTokenClaims(
    string Jti,
    string Sub,
    string ClientId,
    string Scope,
    string? Username,
    IReadOnlyList<string> Audiences,
    DateTime IssuedAt,
    DateTime NotBefore,
    DateTime ExpiresAt);
