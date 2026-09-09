namespace AuthServer.Security;

using System.Globalization;
using System.Security.Claims;

using AuthServer.Models;

using Microsoft.AspNetCore.Authentication.Cookies;

// エンドユーザーのログインセッション (SSO セッション)。
// 方式 A の GET /connect/authorize は資格情報ではなくこの Cookie を見て「誰がログインしているか」を判断する。
// Cookie の発行と破棄は /account/session が行う。Blazor Server のコンポーネントからは応答 Cookie を書けないため、
// M3 後半で作るログイン画面も結局このエンドポイントを叩くことになる。
public static class SessionAuthentication
{
    public const string SchemeName = CookieAuthenticationDefaults.AuthenticationScheme;
    public const string CookieName = "AuthServer.Session";

    private const string AuthTimeClaimType = "auth_time";

    public static IServiceCollection AddAuthServerSession(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        var lifetimeSeconds = configuration.GetValue("AuthServer:SessionLifetimeSeconds", 28800);

        services.AddAuthentication(SchemeName)
            .AddCookie(options =>
            {
                options.Cookie.Name = CookieName;
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;

                // 認可要求はクライアントのサイトからのトップレベル遷移で届くため Lax にする (Strict だと Cookie が送られない)
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.ExpireTimeSpan = TimeSpan.FromSeconds(Math.Max(60, lifetimeSeconds));
                options.SlidingExpiration = true;

                // API サーバーなのでログイン画面へリダイレクトせず、ステータスコードだけを返す
                options.Events.OnRedirectToLogin = context =>
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return Task.CompletedTask;
                };
                options.Events.OnRedirectToAccessDenied = context =>
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    return Task.CompletedTask;
                };
            });

        services.AddAuthorization();
        return services;
    }

    // ログイン成功時にセッションへ載せる主体。auth_time は ID Token の auth_time と max_age の判定に使う。
    public static ClaimsPrincipal CreatePrincipal(User user, DateTime authTime)
    {
        ArgumentNullException.ThrowIfNull(user);

        var identity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, user.UserId),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(AuthTimeClaimType, ToUnixSeconds(authTime).ToString(CultureInfo.InvariantCulture))
            ],
            SchemeName);
        return new ClaimsPrincipal(identity);
    }

    // ログイン中なら利用者とその認証時刻を返す。未ログインなら null。
    public static UserSession? Resolve(ClaimsPrincipal? principal)
    {
        if (principal?.Identity is not { IsAuthenticated: true })
        {
            return null;
        }

        var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var username = principal.FindFirst(ClaimTypes.Name)?.Value;
        if (String.IsNullOrEmpty(userId) || String.IsNullOrEmpty(username))
        {
            return null;
        }

        var authTime = DateTime.UtcNow;
        var raw = principal.FindFirst(AuthTimeClaimType)?.Value;
        if (Int64.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds))
        {
            authTime = DateTimeOffset.FromUnixTimeSeconds(seconds).UtcDateTime;
        }

        return new UserSession(userId, username, authTime);
    }

    public static long ToUnixSeconds(DateTime value) => new DateTimeOffset(value.ToUniversalTime()).ToUnixTimeSeconds();
}

public sealed record UserSession(string UserId, string Username, DateTime AuthTime);
