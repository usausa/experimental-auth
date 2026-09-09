namespace AuthServer.Endpoints;

using AuthServer.Security;
using AuthServer.Services;

using Microsoft.AspNetCore.Authentication;

// エンドユーザーのログインセッション (SSO セッション) を操作する API。
// POST でログインして Cookie を発行し、DELETE で破棄する。GET は現在のセッションを返す。
// ログイン画面 (M3 後半) が入るまでは、方式 A のリダイレクトを画面なしで試すための入口も兼ねる。
public static class SessionEndpoint
{
    public const string Path = "/account/session";

    public static void MapSessionEndpoint(this WebApplication app)
    {
        app.MapPost(Path, HandleSignIn)
            .DisableAntiforgery()
            .WithTags("Session")
            .WithSummary("ログイン (セッション Cookie の発行)")
            .WithDescription("ユーザー資格情報を検証し、セッション Cookie を発行します。GET /connect/authorize (方式 A) はこの Cookie を見て利用者を判断します。")
            .Accepts<IFormCollection>("application/x-www-form-urlencoded")
            .Produces<object>(StatusCodes.Status200OK, "application/json")
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .RequireCors(Security.CorsExtensions.ApiPolicy)
            .RequireRateLimiting(Security.RateLimitingExtensions.AuthenticationPolicy)
            .AllowAnonymous();

        app.MapGet(Path, HandleQuery)
            .WithTags("Session")
            .WithSummary("現在のセッションの取得")
            .WithDescription("セッション Cookie が有効なら、ログイン中の利用者と認証時刻を返します。")
            .Produces<object>(StatusCodes.Status200OK, "application/json")
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .RequireCors(Security.CorsExtensions.ApiPolicy)
            .RequireRateLimiting(Security.RateLimitingExtensions.TokenPolicy)
            .AllowAnonymous();

        app.MapDelete(Path, HandleSignOut)
            .WithTags("Session")
            .WithSummary("ログアウト (セッション Cookie の破棄)")
            .WithDescription("セッション Cookie を破棄します。発行済みのトークンは失効しません (失効は /connect/revoke)。")
            .Produces(StatusCodes.Status204NoContent)
            .RequireCors(Security.CorsExtensions.ApiPolicy)
            .RequireRateLimiting(Security.RateLimitingExtensions.TokenPolicy)
            .AllowAnonymous();
    }

    private static async ValueTask<IResult> HandleSignIn(
        HttpContext context,
        UserService userService,
        AuditLogService auditLog)
    {
        if (!context.Request.HasFormContentType)
        {
            return Error("invalid_request", "Form content required");
        }

        var form = await context.Request.ReadFormAsync(context.RequestAborted);
        var username = form["username"].ToString();
        var password = form["password"].ToString();
        if (String.IsNullOrEmpty(username) || String.IsNullOrEmpty(password))
        {
            return Error("invalid_request", "username and password are required");
        }

        var ip = context.Connection.RemoteIpAddress?.ToString();
        var user = await userService.AuthenticateAsync(username, password);
        if (user is null)
        {
            await auditLog.RecordAsync(new AuditEntry(
                AuditEvents.SessionCreated, AuditOutcome.Failure, null, null, username, ip, "invalid username or password"));
            return Error("access_denied", "Invalid username or password", StatusCodes.Status401Unauthorized);
        }

        var authTime = DateTime.UtcNow;
        await context.SignInAsync(SessionAuthentication.SchemeName, SessionAuthentication.CreatePrincipal(user, authTime));

        await auditLog.RecordAsync(new AuditEntry(
            AuditEvents.SessionCreated, AuditOutcome.Success, null, user.UserId, user.Username, ip, "session cookie issued"));

        return Results.Json(new
        {
            sub = user.UserId,
            username = user.Username,
            auth_time = SessionAuthentication.ToUnixSeconds(authTime)
        });
    }

    private static IResult HandleQuery(HttpContext context)
    {
        var session = SessionAuthentication.Resolve(context.User);
        if (session is null)
        {
            return Error("login_required", "No active session", StatusCodes.Status401Unauthorized);
        }

        return Results.Json(new
        {
            sub = session.UserId,
            username = session.Username,
            auth_time = SessionAuthentication.ToUnixSeconds(session.AuthTime)
        });
    }

    private static async ValueTask<IResult> HandleSignOut(HttpContext context, AuditLogService auditLog)
    {
        var session = SessionAuthentication.Resolve(context.User);
        await context.SignOutAsync(SessionAuthentication.SchemeName);

        if (session is not null)
        {
            await auditLog.RecordAsync(new AuditEntry(
                AuditEvents.SessionEnded, AuditOutcome.Success, null, session.UserId, session.Username,
                context.Connection.RemoteIpAddress?.ToString(), "session cookie cleared"));
        }

        return Results.NoContent();
    }

    private static IResult Error(string code, string description, int status = StatusCodes.Status400BadRequest) =>
        Results.Json(new { error = code, error_description = description }, statusCode: status);
}
