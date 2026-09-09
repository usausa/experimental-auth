namespace AuthServer.Services;

using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

using AuthServer.Models;

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

// クライアント認証 (RFC 6749 §2.3 / RFC 7523 §2.2 / OIDC Core §9)。登録された token_endpoint_auth_method を強制する:
//   client_secret_basic / client_secret_post : シークレットを照合する (送り方の違いは相互に受理する)
//   none                                     : 公開クライアント。client_id のみで、シークレットの送信は拒否する
//   private_key_jwt                          : client_assertion (JWT) を登録済み JWKS で検証し、jti の再利用 (リプレイ) を拒否する
// Token / Revocation / Introspection / Device Authorization の各エンドポイントで共用する。失敗は監査ログに記録する。
public sealed class ClientAuthenticator(
    ClientService clientService,
    ReplayGuardService replayGuardService,
    AuditLogService auditLogService,
    IOptions<AuthServerOptions> options)
{
    public const string JwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    public const string ClientSecretBasic = "client_secret_basic";
    public const string ClientSecretPost = "client_secret_post";
    public const string PrivateKeyJwt = "private_key_jwt";
    public const string None = "none";

    public static readonly string[] SupportedAuthMethods = [ClientSecretBasic, ClientSecretPost, PrivateKeyJwt, None];
    public static readonly string[] SupportedAssertionAlgorithms = [SigningKeyService.Rs256, SigningKeyService.Es256];

    private readonly AuthServerOptions options = options.Value;

    public Task<ClientAuthenticationResult> AuthenticateAsync(HttpContext context, IFormCollection form)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(form);

        var ip = context.Connection.RemoteIpAddress?.ToString();
        var assertion = form["client_assertion"].ToString();
        var assertionType = form["client_assertion_type"].ToString();
        if (!String.IsNullOrEmpty(assertion) || !String.IsNullOrEmpty(assertionType))
        {
            return AuthenticateWithAssertionAsync(context, form, assertion, assertionType, ip);
        }

        return AuthenticateWithSecretAsync(context, form, ip);
    }

    private async Task<ClientAuthenticationResult> AuthenticateWithSecretAsync(HttpContext context, IFormCollection form, string? ip)
    {
        var (clientId, secret) = ResolveCredentials(context, form);
        if (String.IsNullOrEmpty(clientId))
        {
            return await FailAsync(null, ip, "client_id is required");
        }

        var client = await clientService.QueryClientAsync(clientId);
        if (client is null)
        {
            return await FailAsync(clientId, ip, "Client authentication failed");
        }

        switch (client.TokenEndpointAuthMethod)
        {
            case None:
                if (!String.IsNullOrEmpty(secret))
                {
                    return await FailAsync(clientId, ip, "Client is registered as a public client (none); client_secret must not be sent");
                }

                return ClientAuthenticationResult.Success(client);
            case PrivateKeyJwt:
                return await FailAsync(clientId, ip, "Client must authenticate with private_key_jwt (client_assertion)");
            case ClientSecretBasic:
            case ClientSecretPost:
                if (String.IsNullOrEmpty(secret) || !ClientService.ValidateSecret(client, secret))
                {
                    return await FailAsync(clientId, ip, "Client authentication failed");
                }

                return ClientAuthenticationResult.Success(client);
            default:
                return await FailAsync(clientId, ip, $"Unsupported token_endpoint_auth_method '{client.TokenEndpointAuthMethod}'");
        }
    }

    // private_key_jwt: iss = sub = client_id、aud = 発行者識別子またはエンドポイント URL、exp 必須、jti 必須かつ一回限り。
    // 署名はクライアントに登録された JWKS (RS256 / ES256) で検証する。
    private async Task<ClientAuthenticationResult> AuthenticateWithAssertionAsync(
        HttpContext context, IFormCollection form, string assertion, string assertionType, string? ip)
    {
        if (!String.Equals(assertionType, JwtBearerAssertionType, StringComparison.Ordinal))
        {
            return await FailAsync(null, ip, "client_assertion_type must be " + JwtBearerAssertionType);
        }

        if (String.IsNullOrEmpty(assertion))
        {
            return await FailAsync(null, ip, "client_assertion is required");
        }

        var handler = new JsonWebTokenHandler();
        if (!handler.CanReadToken(assertion))
        {
            return await FailAsync(null, ip, "client_assertion is not a valid JWT");
        }

        var unverified = handler.ReadJsonWebToken(assertion);
        var clientId = unverified.Issuer;
        if (String.IsNullOrEmpty(clientId) || !String.Equals(unverified.Subject, clientId, StringComparison.Ordinal))
        {
            return await FailAsync(clientId, ip, "client_assertion iss and sub must both be the client_id");
        }

        // client_id をフォームでも送ってきた場合は一致を要求する (RFC 7521 §4.2)
        var formClientId = form["client_id"].ToString();
        if (!String.IsNullOrEmpty(formClientId) && !String.Equals(formClientId, clientId, StringComparison.Ordinal))
        {
            return await FailAsync(clientId, ip, "client_id does not match the client_assertion");
        }

        var client = await clientService.QueryClientAsync(clientId);
        if (client is null)
        {
            return await FailAsync(clientId, ip, "Client authentication failed");
        }

        if (!String.Equals(client.TokenEndpointAuthMethod, PrivateKeyJwt, StringComparison.Ordinal))
        {
            return await FailAsync(clientId, ip, "Client is not registered for private_key_jwt");
        }

        if (String.IsNullOrEmpty(client.Jwks))
        {
            return await FailAsync(clientId, ip, "Client has no registered JWKS");
        }

        JsonWebKeySet jwks;
        try
        {
            jwks = new JsonWebKeySet(client.Jwks);
        }
        catch (ArgumentException)
        {
            return await FailAsync(clientId, ip, "Client JWKS is invalid");
        }
        catch (JsonException)
        {
            return await FailAsync(clientId, ip, "Client JWKS is invalid");
        }

        var issuer = options.Issuer.TrimEnd('/');
        var parameters = new TokenValidationParameters
        {
            ValidIssuer = clientId,
            ValidAudiences = [issuer, issuer + "/", issuer + "/connect/token", issuer + context.Request.Path],
            IssuerSigningKeys = jwks.GetSigningKeys(),
            ValidAlgorithms = SupportedAssertionAlgorithms,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30)
        };

        var result = await handler.ValidateTokenAsync(assertion, parameters);
        if (!result.IsValid || (result.SecurityToken is not JsonWebToken jwt))
        {
            return await FailAsync(clientId, ip, "client_assertion is invalid: " + DescribeFailure(result.Exception));
        }

        var jti = jwt.Id;
        if (String.IsNullOrEmpty(jti))
        {
            return await FailAsync(clientId, ip, "client_assertion must contain a jti");
        }

        // 寿命の上限。長寿命のアサーションは盗まれたときの被害が大きい (RFC 7523 §3 / OIDC Core §9)
        var issuedAt = jwt.IssuedAt == DateTime.MinValue ? DateTime.UtcNow : jwt.IssuedAt;
        if ((jwt.ValidTo - issuedAt).TotalSeconds > options.ClientAssertionMaxLifetimeSeconds)
        {
            return await FailAsync(clientId, ip, $"client_assertion lifetime must not exceed {options.ClientAssertionMaxLifetimeSeconds} seconds");
        }

        // jti の一回性 (リプレイ検出)。exp まで記録し、同じアサーションの再提示を拒否する
        if (!await replayGuardService.TryRegisterAsync(ReplayGuardService.ClientAssertionJti, clientId + ":" + jti, clientId, jwt.ValidTo))
        {
            await auditLogService.RecordAsync(new AuditEntry(
                AuditEvents.ReplayDetected, AuditOutcome.Failure, clientId, null, null, ip, "client_assertion jti reused: " + jti));
            return ClientAuthenticationResult.Failure(clientId, "client_assertion has already been used (jti replay)");
        }

        return ClientAuthenticationResult.Success(client);
    }

    private async Task<ClientAuthenticationResult> FailAsync(string? clientId, string? ip, string description)
    {
        await auditLogService.RecordAsync(new AuditEntry(AuditEvents.ClientAuth, AuditOutcome.Failure, clientId, null, null, ip, description));
        return ClientAuthenticationResult.Failure(clientId, description);
    }

    private static string DescribeFailure(Exception? exception) =>
        exception switch
        {
            SecurityTokenExpiredException => "assertion expired",
            SecurityTokenNotYetValidException => "assertion not yet valid",
            SecurityTokenInvalidAudienceException => "aud must be the issuer or the token endpoint URL",
            SecurityTokenInvalidIssuerException => "iss must be the client_id",
            SecurityTokenNoExpirationException => "exp is required",
            SecurityTokenInvalidAlgorithmException => "alg must be RS256 or ES256",
            SecurityTokenSignatureKeyNotFoundException => "no registered key matches the assertion (check kid)",
            SecurityTokenInvalidSignatureException => "signature verification failed",
            _ => "validation failed"
        };

    // クライアント認証情報の取り出し (RFC 6749 §2.3.1)。
    // client_secret_basic (Authorization: Basic) を優先し、なければ client_secret_post (フォーム) を使う。
    private static (string ClientId, string? Secret) ResolveCredentials(HttpContext context, IFormCollection form)
    {
        var authHeader = context.Request.Headers.Authorization.ToString();
        if (!String.IsNullOrEmpty(authHeader) &&
            AuthenticationHeaderValue.TryParse(authHeader, out var parsed) &&
            String.Equals(parsed.Scheme, "Basic", StringComparison.OrdinalIgnoreCase) &&
            !String.IsNullOrEmpty(parsed.Parameter))
        {
            try
            {
                var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(parsed.Parameter));
                var idx = decoded.IndexOf(':', StringComparison.Ordinal);
                if (idx >= 0)
                {
                    var id = Uri.UnescapeDataString(decoded[..idx]);
                    var secret = Uri.UnescapeDataString(decoded[(idx + 1)..]);
                    return (id, secret);
                }
            }
            catch (FormatException)
            {
                // Base64 として不正な場合はフォームパラメーターにフォールバックする
            }
        }

        return (form["client_id"].ToString(), form["client_secret"].ToString());
    }
}

// Client が非 null なら認証成功。失敗時は ErrorDescription をそのまま invalid_client の説明に使える (シークレットは含まない)。
public sealed record ClientAuthenticationResult(Client? Client, string? ClientId, string? ErrorDescription)
{
    public static ClientAuthenticationResult Success(Client client)
    {
        ArgumentNullException.ThrowIfNull(client);
        return new(client, client.ClientId, null);
    }

    public static ClientAuthenticationResult Failure(string? clientId, string description) => new(null, clientId, description);
}
