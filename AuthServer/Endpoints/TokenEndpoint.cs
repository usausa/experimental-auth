namespace AuthServer.Endpoints;

using System.Net.Http.Headers;
using System.Text;

using AuthServer.Models;
using AuthServer.Services;

public static class TokenEndpoint
{
    public static void MapTokenEndpoint(this WebApplication app)
    {
        app.MapPost("/connect/token", HandleToken).DisableAntiforgery();
    }

    //--------------------------------------------------------------------------------
    // トークン発行エンドポイント
    // POST /connect/token
    // OAuth 2.0 / OpenID Connect のトークンを発行する標準エンドポイント（RFC 6749）。
    // サポートするグラントタイプ: client_credentials / authorization_code / refresh_token。
    // クライアント認証は client_secret_post または client_secret_basic に対応。
    //--------------------------------------------------------------------------------

    private static async ValueTask<IResult> HandleToken(
        HttpContext context,
        ClientService clientService,
        TokenService tokenService,
        ResourceServerService resourceServerService)
    {
        if (!context.Request.HasFormContentType)
        {
            return Error("invalid_request", "Form content required");
        }

        var form = await context.Request.ReadFormAsync(context.RequestAborted);
        var grantType = form["grant_type"].ToString();

        if (string.IsNullOrEmpty(grantType))
        {
            return Error("invalid_request", "grant_type is required");
        }

        var (clientId, clientSecret) = ResolveClientCredentials(context, form);
        if (string.IsNullOrEmpty(clientId))
        {
            return Error("invalid_client", "client_id is required", StatusCodes.Status401Unauthorized);
        }

        var client = await clientService.QueryClientAsync(clientId);
        if (client is null || !ClientService.ValidateSecret(client, clientSecret))
        {
            return Error("invalid_client", "Client authentication failed", StatusCodes.Status401Unauthorized);
        }

        // Resolve audience from `resource` parameter or fall back to first active resource server.
        var resourceParam = form["resource"].ToString();
        string? audience;
        if (!string.IsNullOrEmpty(resourceParam))
        {
            var servers = await resourceServerService.QueryActiveResourceServerListAsync();
            var matched = servers.FirstOrDefault(s =>
                string.Equals(s.Audience, resourceParam, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(s.ResourceServerId, resourceParam, StringComparison.OrdinalIgnoreCase));
            if (matched is null)
            {
                return Error("invalid_target", $"Resource '{resourceParam}' is not registered");
            }
            audience = matched.Audience;
        }
        else
        {
            var servers = await resourceServerService.QueryActiveResourceServerListAsync();
            audience = servers.Count > 0 ? servers[0].Audience : null;
        }

        if (audience is null)
        {
            return Error("server_error", "No active resource server is configured");
        }

        return grantType switch
        {
            "client_credentials" => HandleClientCredentials(client, form, tokenService, audience),
            _ => Error("unsupported_grant_type", $"grant_type '{grantType}' is not supported in Phase 1")
        };
    }

    private static IResult HandleClientCredentials(Client client, IFormCollection form, TokenService tokenService, string audience)
    {
        if (!client.GrantTypes.Contains("client_credentials", StringComparison.Ordinal))
        {
            return Error("unauthorized_client", "Client is not allowed to use client_credentials grant");
        }

        var requested = form["scope"].ToString();
        var allowed = client.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        string[] granted;

        if (string.IsNullOrEmpty(requested))
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

        var scope = string.Join(' ', granted);
        var result = tokenService.IssueClientCredentialsToken(client.ClientId, scope, audience);

        return Results.Json(new
        {
            access_token = result.AccessToken,
            token_type = "Bearer",
            expires_in = result.ExpiresInSeconds,
            scope = result.Scope
        });
    }

    private static (string ClientId, string? Secret) ResolveClientCredentials(HttpContext context, IFormCollection form)
    {
        // RFC 6749 §2.3.1: prefer Authorization: Basic.
        var authHeader = context.Request.Headers.Authorization.ToString();
        if (!string.IsNullOrEmpty(authHeader) &&
            AuthenticationHeaderValue.TryParse(authHeader, out var parsed) &&
            string.Equals(parsed.Scheme, "Basic", StringComparison.OrdinalIgnoreCase) &&
            !string.IsNullOrEmpty(parsed.Parameter))
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
