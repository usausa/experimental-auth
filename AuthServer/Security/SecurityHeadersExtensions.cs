namespace AuthServer.Security;

// セキュリティヘッダー (SEC-15)。全応答に共通の防御を載せる。
//
// 認可サーバー固有の勘所が 2 つある。
//   - Referrer-Policy: 認可応答の URL には認可コードが載る。リファラー経由で外部へ漏れないよう no-referrer にする
//   - frame-ancestors / X-Frame-Options: ログイン画面や同意画面をフレームに埋め込ませない (クリックジャッキング対策)
//
// CSP は Blazor Server (MudBlazor) の管理画面が動く範囲に合わせている。
//   - MudBlazor はインラインの style 属性を多用するため style-src に 'unsafe-inline' が要る
//   - Roboto を Google Fonts から読むため fonts.googleapis.com / fonts.gstatic.com を許可する (App.razor)
//   - インラインの <script> は無いので script-src は 'self' だけでよい
//   - Blazor Server の SignalR 接続は同一オリジンなので connect-src 'self' で足りる
// form_post の認可応答だけは相手先へ POST するため、AuthorizeResponse が専用の CSP で上書きする。
public static class SecurityHeadersExtensions
{
    public const string DefaultContentSecurityPolicy =
        "default-src 'self'; " +
        "base-uri 'self'; " +
        "object-src 'none'; " +
        "frame-ancestors 'none'; " +
        "form-action 'self'; " +
        "img-src 'self' data:; " +
        "font-src 'self' https://fonts.gstatic.com; " +
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
        "script-src 'self'; " +
        "connect-src 'self'";

    private const string PermissionsPolicy =
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()";

    public static IApplicationBuilder UseAuthServerSecurityHeaders(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        return app.Use(async (context, next) =>
        {
            var headers = context.Response.Headers;
            headers.XContentTypeOptions = "nosniff";
            headers.XFrameOptions = "DENY";

            // 認可コードを含む URL がリファラーとして送られないようにする
            headers["Referrer-Policy"] = "no-referrer";
            headers["Permissions-Policy"] = PermissionsPolicy;
            headers.ContentSecurityPolicy = DefaultContentSecurityPolicy;

            await next(context);
        });
    }
}
