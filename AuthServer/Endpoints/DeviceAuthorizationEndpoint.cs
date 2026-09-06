namespace AuthServer.Endpoints;

using AuthServer.Models;
using AuthServer.Services;

using Microsoft.Extensions.Options;

// Device Authorization Endpoint (RFC 8628 §3.1 / §3.2)
// POST /connect/device/authorize
// 入力制約デバイスや CLI が device_code / user_code を取得する。ユーザーは別のブラウザで verification_uri を開き、
// user_code を入力して承認する。クライアントは interval 秒ごとにトークンエンドポイントをポーリングする。
public static class DeviceAuthorizationEndpoint
{
    public const string GrantType = "urn:ietf:params:oauth:grant-type:device_code";

    public static void MapDeviceAuthorizationEndpoint(this WebApplication app)
    {
        app.MapPost("/connect/device/authorize", HandleDeviceAuthorization)
            .DisableAntiforgery()
            .WithTags("Authorization")
            .WithSummary("デバイス認可要求 (Device Authorization Grant)")
            .WithDescription("device_code と user_code を発行します(RFC 8628 §3.2)。ユーザーは verification_uri で user_code を入力して承認し、クライアントは interval 秒ごとに /connect/token をポーリングします。")
            .Accepts<IFormCollection>("application/x-www-form-urlencoded")
            .Produces<object>(StatusCodes.Status200OK, "application/json")
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .AllowAnonymous();
    }

    private static async ValueTask<IResult> HandleDeviceAuthorization(
        HttpContext context,
        ClientService clientService,
        DeviceCodeService deviceCodeService,
        IOptions<AuthServerOptions> options)
    {
        if (!context.Request.HasFormContentType)
        {
            return Error("invalid_request", "Form content required");
        }

        var form = await context.Request.ReadFormAsync(context.RequestAborted);

        // 公開クライアントは client_id のみ、機密クライアントは client_secret も検証する (RFC 8628 §3.1 → RFC 6749 §3.2.1)
        var (clientId, clientSecret) = ClientAuthentication.ResolveCredentials(context, form);
        if (String.IsNullOrEmpty(clientId))
        {
            return Error("invalid_client", "client_id is required", StatusCodes.Status401Unauthorized);
        }

        var client = await clientService.QueryClientAsync(clientId);
        if ((client is null) || !ClientService.ValidateSecret(client, clientSecret))
        {
            return Error("invalid_client", "Client authentication failed", StatusCodes.Status401Unauthorized);
        }

        if (!client.AllowsGrantType(GrantType))
        {
            return Error("unauthorized_client", "Client is not allowed to use the device_code grant");
        }

        // スコープ検証 (省略時はクライアントに許可された全スコープ)
        var allowed = client.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var requested = form["scope"].ToString();
        string[] granted;
        if (String.IsNullOrEmpty(requested))
        {
            granted = allowed;
        }
        else
        {
            granted = requested.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            foreach (var s in granted)
            {
                if (Array.IndexOf(allowed, s) < 0)
                {
                    return Error("invalid_scope", $"Scope '{s}' is not allowed for this client");
                }
            }
        }

        var authorization = await deviceCodeService.IssueAsync(client.ClientId, String.Join(' ', granted));
        var issuer = options.Value.Issuer.TrimEnd('/');
        var verificationUri = $"{issuer}/account/device";

        return Results.Json(new
        {
            device_code = authorization.DeviceCode,
            user_code = authorization.UserCode,
            verification_uri = verificationUri,
            verification_uri_complete = $"{verificationUri}?user_code={Uri.EscapeDataString(authorization.UserCode)}",
            expires_in = authorization.ExpiresInSeconds,
            interval = authorization.IntervalSeconds
        });
    }

    private static IResult Error(string code, string description, int status = StatusCodes.Status400BadRequest) =>
        Results.Json(new { error = code, error_description = description }, statusCode: status);
}
