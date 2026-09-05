namespace AuthServer.Endpoints;

using System.Net.Http.Headers;
using System.Text;

using AuthServer.Models;
using AuthServer.Services;

public static class TokenEndpoint
{
    public static void MapTokenEndpoint(this WebApplication app)
    {
        app.MapPost("/connect/token", HandleToken)
            .DisableAntiforgery()
            .WithTags("Token")
            .WithSummary("トークンの発行")
            .WithDescription("OAuth 2.0 / OpenID Connect のトークンを発行します(RFC 6749)。サポートするグラントタイプ: client_credentials / authorization_code / refresh_token。クライアント認証は client_secret_post または client_secret_basic に対応。")
            .Accepts<IFormCollection>("application/x-www-form-urlencoded")
            .Produces<object>(StatusCodes.Status200OK, "application/json")
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .AllowAnonymous();
    }

    //--------------------------------------------------------------------------------
    // トークン発行エンドポイント
    // POST /connect/token
    // OAuth 2.0 / OpenID Connect のトークンを発行する標準エンドポイント(RFC 6749)。
    // サポートするグラントタイプ: client_credentials / authorization_code / refresh_token。
    // クライアント認証は client_secret_post または client_secret_basic に対応。
    //--------------------------------------------------------------------------------

    private static async ValueTask<IResult> HandleToken(
        HttpContext context,
        ClientService clientService,
        TokenService tokenService,
        ResourceServerService resourceServerService,
        AuthorizationCodeService codeService,
        RefreshTokenService refreshTokenService,
        UserService userService)
    {
        if (!context.Request.HasFormContentType)
        {
            return Error("invalid_request", "Form content required");
        }

        var form = await context.Request.ReadFormAsync(context.RequestAborted);
        var grantType = form["grant_type"].ToString();

        if (String.IsNullOrEmpty(grantType))
        {
            return Error("invalid_request", "grant_type is required");
        }

        var (clientId, clientSecret) = ResolveClientCredentials(context, form);
        if (String.IsNullOrEmpty(clientId))
        {
            return Error("invalid_client", "client_id is required", StatusCodes.Status401Unauthorized);
        }

        var client = await clientService.QueryClientAsync(clientId);
        if ((client is null) || !ClientService.ValidateSecret(client, clientSecret))
        {
            return Error("invalid_client", "Client authentication failed", StatusCodes.Status401Unauthorized);
        }

        return grantType switch
        {
            "client_credentials" => await HandleClientCredentials(client, form, tokenService, resourceServerService),
            "authorization_code" => await HandleAuthorizationCode(client, form, tokenService, codeService, refreshTokenService, userService, resourceServerService),
            "refresh_token" => await HandleRefreshToken(client, form, tokenService, refreshTokenService, userService, resourceServerService),
            _ => Error("unsupported_grant_type", $"grant_type '{grantType}' is not supported")
        };
    }

    private static async ValueTask<IResult> HandleClientCredentials(Client client, IFormCollection form, TokenService tokenService, ResourceServerService resourceServerService)
    {
        if (!client.AllowsGrantType("client_credentials"))
        {
            return Error("unauthorized_client", "Client is not allowed to use client_credentials grant");
        }

        var audience = await ResolveAudience(form, resourceServerService);
        if (audience is null)
        {
            return Error("server_error", "No active resource server is configured");
        }

        var requested = form["scope"].ToString();
        var allowed = client.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        string[] granted;

        if (String.IsNullOrEmpty(requested))
        {
            granted = allowed;
        }
        else
        {
            var requestedScopes = requested.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            foreach (var s in requestedScopes)
            {
                if (Array.IndexOf(allowed, s) < 0)
                {
                    return Error("invalid_scope", $"Scope '{s}' is not allowed for this client");
                }
            }
            granted = requestedScopes;
        }

        var scope = String.Join(' ', granted);
        var result = tokenService.IssueClientCredentialsToken(client.ClientId, scope, audience);

        return Results.Json(new
        {
            access_token = result.AccessToken,
            token_type = "Bearer",
            expires_in = result.ExpiresInSeconds,
            scope = result.Scope
        });
    }

    private static async ValueTask<IResult> HandleAuthorizationCode(
        Client client,
        IFormCollection form,
        TokenService tokenService,
        AuthorizationCodeService codeService,
        RefreshTokenService refreshTokenService,
        UserService userService,
        ResourceServerService resourceServerService)
    {
        if (!client.AllowsGrantType("authorization_code"))
        {
            return Error("unauthorized_client", "Client is not allowed to use authorization_code grant");
        }

        var code = form["code"].ToString();
        if (String.IsNullOrEmpty(code))
        {
            return Error("invalid_request", "code is required");
        }

        var redirectUri = form["redirect_uri"].ToString();
        if (String.IsNullOrEmpty(redirectUri))
        {
            return Error("invalid_request", "redirect_uri is required");
        }

        var codeVerifier = form["code_verifier"].ToString();
        if (String.IsNullOrEmpty(codeVerifier))
        {
            return Error("invalid_request", "code_verifier is required (PKCE)");
        }

        // 認可コード消費
        var info = await codeService.ConsumeAsync(code);
        if (info is null)
        {
            return Error("invalid_grant", "Authorization code is invalid or expired");
        }

        if (!String.Equals(info.ClientId, client.ClientId, StringComparison.Ordinal))
        {
            return Error("invalid_grant", "Authorization code was not issued to this client");
        }

        if (!String.Equals(info.RedirectUri, redirectUri, StringComparison.Ordinal))
        {
            return Error("invalid_grant", "redirect_uri does not match");
        }

        // PKCE 検証
        if ((info.CodeChallenge is not null) && (info.CodeChallengeMethod is not null))
        {
            if (!AuthorizationCodeService.VerifyPkce(info.CodeChallenge, info.CodeChallengeMethod, codeVerifier))
            {
                return Error("invalid_grant", "code_verifier is invalid");
            }
        }

        var user = await userService.QueryUserAsync(info.UserId);
        if ((user is null) || !user.IsActive)
        {
            return Error("invalid_grant", "User not found or inactive");
        }

        var audience = await ResolveAudience(form, resourceServerService);
        if (audience is null)
        {
            return Error("server_error", "No active resource server is configured");
        }

        var accessTokenResult = tokenService.IssueAuthorizationCodeToken(
            client.ClientId, user.UserId, user.Username, info.Scopes, audience);

        var scopes = info.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var includesOpenId = Array.IndexOf(scopes, "openid") >= 0;

        string? idToken = null;
        if (includesOpenId)
        {
            idToken = tokenService.IssueIdToken(client.ClientId, user.UserId, user, info.Nonce, scopes, info.AuthTime, accessTokenResult.AccessToken);
        }

        // refresh_token グラントが許可されていれば発行
        string? refreshToken = null;
        if (client.AllowsGrantType("refresh_token"))
        {
            refreshToken = await refreshTokenService.IssueAsync(client.ClientId, user.UserId, info.Scopes);
        }

        return Results.Json(new
        {
            access_token = accessTokenResult.AccessToken,
            token_type = "Bearer",
            expires_in = accessTokenResult.ExpiresInSeconds,
            scope = accessTokenResult.Scope,
            id_token = idToken,
            refresh_token = refreshToken
        });
    }

    private static async ValueTask<IResult> HandleRefreshToken(
        Client client,
        IFormCollection form,
        TokenService tokenService,
        RefreshTokenService refreshTokenService,
        UserService userService,
        ResourceServerService resourceServerService)
    {
        if (!client.AllowsGrantType("refresh_token"))
        {
            return Error("unauthorized_client", "Client is not allowed to use refresh_token grant");
        }

        var token = form["refresh_token"].ToString();
        if (String.IsNullOrEmpty(token))
        {
            return Error("invalid_request", "refresh_token is required");
        }

        var rotated = await refreshTokenService.RotateAsync(token);
        if (rotated is null)
        {
            return Error("invalid_grant", "Refresh token is invalid, expired, or revoked");
        }

        var (info, newRefreshToken) = rotated.Value;

        if (!String.Equals(info.ClientId, client.ClientId, StringComparison.Ordinal))
        {
            return Error("invalid_grant", "Refresh token was not issued to this client");
        }

        var user = await userService.QueryUserAsync(info.UserId);
        if ((user is null) || !user.IsActive)
        {
            return Error("invalid_grant", "User not found or inactive");
        }

        var audience = await ResolveAudience(form, resourceServerService);
        if (audience is null)
        {
            return Error("server_error", "No active resource server is configured");
        }

        var accessTokenResult = tokenService.IssueAuthorizationCodeToken(
            client.ClientId, user.UserId, user.Username, info.Scopes, audience);

        return Results.Json(new
        {
            access_token = accessTokenResult.AccessToken,
            token_type = "Bearer",
            expires_in = accessTokenResult.ExpiresInSeconds,
            scope = accessTokenResult.Scope,
            refresh_token = newRefreshToken
        });
    }

    private static async Task<string?> ResolveAudience(IFormCollection form, ResourceServerService resourceServerService)
    {
        var resourceParam = form["resource"].ToString();
        if (!String.IsNullOrEmpty(resourceParam))
        {
            var servers = await resourceServerService.QueryActiveResourceServerListAsync();
            var matched = servers.FirstOrDefault(s =>
                String.Equals(s.Audience, resourceParam, StringComparison.OrdinalIgnoreCase) ||
                String.Equals(s.ResourceServerId, resourceParam, StringComparison.OrdinalIgnoreCase));
            return matched?.Audience;
        }
        else
        {
            var servers = await resourceServerService.QueryActiveResourceServerListAsync();
            return servers.Count > 0 ? servers[0].Audience : null;
        }
    }

    private static (string ClientId, string? Secret) ResolveClientCredentials(HttpContext context, IFormCollection form)
    {
        // RFC 6749 §2.3.1: prefer Authorization: Basic.
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
                // Fall through to form parameters.
            }
        }

        return (form["client_id"].ToString(), form["client_secret"].ToString());
    }

    private static IResult Error(string code, string description, int status = StatusCodes.Status400BadRequest) =>
        Results.Json(new { error = code, error_description = description }, statusCode: status);
}
