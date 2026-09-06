namespace AuthServer.Endpoints;

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
            .WithDescription("OAuth 2.0 / OpenID Connect のトークンを発行します(RFC 6749)。サポートするグラントタイプ: client_credentials / authorization_code / refresh_token / urn:ietf:params:oauth:grant-type:device_code。クライアント認証は client_secret_post または client_secret_basic に対応。")
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
    // サポートするグラントタイプ: client_credentials / authorization_code / refresh_token / device_code (RFC 8628)。
    // クライアント認証は client_secret_post または client_secret_basic に対応。
    //--------------------------------------------------------------------------------

    private static async ValueTask<IResult> HandleToken(
        HttpContext context,
        ClientService clientService,
        TokenService tokenService,
        ResourceServerService resourceServerService,
        AuthorizationCodeService codeService,
        RefreshTokenService refreshTokenService,
        DeviceCodeService deviceCodeService,
        UserService userService,
        ILoggerFactory loggerFactory)
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

        return grantType switch
        {
            "client_credentials" => await HandleClientCredentials(client, form, tokenService, resourceServerService),
            "authorization_code" => await HandleAuthorizationCode(client, form, tokenService, codeService, refreshTokenService, userService, resourceServerService, loggerFactory),
            "refresh_token" => await HandleRefreshToken(client, form, tokenService, refreshTokenService, userService, resourceServerService),
            DeviceAuthorizationEndpoint.GrantType => await HandleDeviceCode(client, form, tokenService, deviceCodeService, refreshTokenService, userService, resourceServerService),
            _ => Error("unsupported_grant_type", $"grant_type '{grantType}' is not supported")
        };
    }

    private static async ValueTask<IResult> HandleClientCredentials(Client client, IFormCollection form, TokenService tokenService, ResourceServerService resourceServerService)
    {
        if (!client.AllowsGrantType("client_credentials"))
        {
            return Error("unauthorized_client", "Client is not allowed to use client_credentials grant");
        }

        var audiences = await ResolveAudiencesAsync(form, resourceServerService, null);
        if (audiences.Error is not null)
        {
            return audiences.Error;
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
        var result = tokenService.IssueClientCredentialsToken(client.ClientId, scope, audiences.Values);

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
        ResourceServerService resourceServerService,
        ILoggerFactory loggerFactory)
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

        // 認可コード消費 (ワンタイム)。消費済みコードの再提示は漏洩の疑いとみなし、
        // そのコードから派生したリフレッシュトークンのファミリーをすべて失効させる (RFC 6749 §4.1.2)
        var consume = await codeService.ConsumeAsync(code);
        if (consume.Status == AuthorizationCodeConsumeStatus.Reused)
        {
            var revokedCount = await refreshTokenService.RevokeFamilyAsync(consume.Info!.CodeHash);
            loggerFactory.CreateLogger("TokenEndpoint").LogWarning(
                "Authorization code reuse detected for client {ClientId}; revoked {Count} refresh token(s).",
                consume.Info.ClientId, revokedCount);
            return Error("invalid_grant", "Authorization code is invalid or expired");
        }

        if (consume.Status != AuthorizationCodeConsumeStatus.Success)
        {
            return Error("invalid_grant", "Authorization code is invalid or expired");
        }

        var info = consume.Info!;

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

        var audiences = await ResolveAudiencesAsync(form, resourceServerService, null);
        if (audiences.Error is not null)
        {
            return audiences.Error;
        }

        var accessTokenResult = tokenService.IssueAuthorizationCodeToken(
            client.ClientId, user.UserId, user.Username, info.Scopes, audiences.Values);

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
            refreshToken = await refreshTokenService.IssueAsync(client.ClientId, user.UserId, info.Scopes, info.CodeHash, audiences.Values);
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

        // resource を省略すれば元の audience を維持し、指定すれば元の範囲内に絞り込む (RFC 8707 §2.2)
        var audiences = await ResolveAudiencesAsync(form, resourceServerService, info.Audiences.Count > 0 ? info.Audiences : null);
        if (audiences.Error is not null)
        {
            return audiences.Error;
        }

        var accessTokenResult = tokenService.IssueAuthorizationCodeToken(
            client.ClientId, user.UserId, user.Username, info.Scopes, audiences.Values);

        return Results.Json(new
        {
            access_token = accessTokenResult.AccessToken,
            token_type = "Bearer",
            expires_in = accessTokenResult.ExpiresInSeconds,
            scope = accessTokenResult.Scope,
            refresh_token = newRefreshToken
        });
    }

    // Device Authorization Grant (RFC 8628 §3.4 / §3.5)。クライアントは interval 秒ごとにポーリングし、
    // authorization_pending / slow_down / access_denied / expired_token を受け取りながらユーザーの承認を待つ。
    private static async ValueTask<IResult> HandleDeviceCode(
        Client client,
        IFormCollection form,
        TokenService tokenService,
        DeviceCodeService deviceCodeService,
        RefreshTokenService refreshTokenService,
        UserService userService,
        ResourceServerService resourceServerService)
    {
        if (!client.AllowsGrantType(DeviceAuthorizationEndpoint.GrantType))
        {
            return Error("unauthorized_client", "Client is not allowed to use the device_code grant");
        }

        var deviceCode = form["device_code"].ToString();
        if (String.IsNullOrEmpty(deviceCode))
        {
            return Error("invalid_request", "device_code is required");
        }

        var poll = await deviceCodeService.PollAsync(deviceCode, client.ClientId);
        switch (poll.Status)
        {
            case DevicePollStatus.Pending:
                return Error("authorization_pending", "The user has not yet approved the request");
            case DevicePollStatus.SlowDown:
                return Error("slow_down", "Polling too frequently; increase the interval by 5 seconds");
            case DevicePollStatus.Denied:
                return Error("access_denied", "The user denied the request");
            case DevicePollStatus.Expired:
                return Error("expired_token", "The device_code has expired");
            case DevicePollStatus.Authorized:
                break;
            default:
                return Error("invalid_grant", "device_code is invalid");
        }

        var record = poll.Record!;
        var user = record.UserId is null ? null : await userService.QueryUserAsync(record.UserId);
        if ((user is null) || !user.IsActive)
        {
            return Error("invalid_grant", "User not found or inactive");
        }

        var audiences = await ResolveAudiencesAsync(form, resourceServerService, null);
        if (audiences.Error is not null)
        {
            return audiences.Error;
        }

        var accessTokenResult = tokenService.IssueAuthorizationCodeToken(
            client.ClientId, user.UserId, user.Username, record.Scopes, audiences.Values);

        var scopes = record.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        string? idToken = null;
        if (Array.IndexOf(scopes, "openid") >= 0)
        {
            // auth_time はユーザーが承認画面で認証した時刻。nonce はデバイスフローの要求に含まれない
            idToken = tokenService.IssueIdToken(
                client.ClientId, user.UserId, user, null, scopes, record.AuthorizedAt ?? DateTime.UtcNow, accessTokenResult.AccessToken);
        }

        // デバイスコードのハッシュをファミリーの識別子にする (認可コードの source_code_hash と同じ役割)
        string? refreshToken = null;
        if (client.AllowsGrantType("refresh_token"))
        {
            refreshToken = await refreshTokenService.IssueAsync(client.ClientId, user.UserId, record.Scopes, record.DeviceCodeHash, audiences.Values);
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

    // Resource Indicators (RFC 8707): resource パラメーター (複数可) を登録済みリソースサーバーの audience に解決する。
    // 省略時は allowed (リフレッシュトークンに保存した元の audience) か、既定のリソースサーバー 1 つを使う。
    // 絶対 URI でない・フラグメントを含む・未登録・allowed の範囲外なら invalid_target を返す。
    private static async Task<AudienceResolution> ResolveAudiencesAsync(
        IFormCollection form,
        ResourceServerService resourceServerService,
        IReadOnlyList<string>? allowed)
    {
        var servers = await resourceServerService.QueryActiveResourceServerListAsync();
        var requested = form["resource"]
            .Where(v => !String.IsNullOrEmpty(v))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (requested.Count == 0)
        {
            if ((allowed is not null) && (allowed.Count > 0))
            {
                return new AudienceResolution(allowed, null);
            }

            return servers.Count > 0
                ? new AudienceResolution([servers[0].Audience], null)
                : new AudienceResolution([], Error("server_error", "No active resource server is configured"));
        }

        var resolved = new List<string>(requested.Count);
        foreach (var value in requested)
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || !String.IsNullOrEmpty(uri.Fragment))
            {
                return new AudienceResolution([], InvalidTarget());
            }

            var matched = servers.FirstOrDefault(s => String.Equals(s.Audience, value, StringComparison.OrdinalIgnoreCase));
            if (matched is null)
            {
                return new AudienceResolution([], InvalidTarget());
            }

            if ((allowed is not null) && !allowed.Contains(matched.Audience, StringComparer.OrdinalIgnoreCase))
            {
                return new AudienceResolution([], InvalidTarget());
            }

            resolved.Add(matched.Audience);
        }

        return new AudienceResolution(resolved, null);
    }

    private static IResult InvalidTarget() =>
        Error("invalid_target", "The requested resource is invalid, missing, unknown, or malformed");

    private static IResult Error(string code, string description, int status = StatusCodes.Status400BadRequest) =>
        Results.Json(new { error = code, error_description = description }, statusCode: status);
}

// resource の解決結果。Error が非 null なら Values は空で、呼び出し側はそのまま返す。
internal sealed record AudienceResolution(IReadOnlyList<string> Values, IResult? Error);
