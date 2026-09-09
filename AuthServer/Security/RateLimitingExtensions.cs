namespace AuthServer.Security;

using System.Globalization;
using System.Threading.RateLimiting;

using AuthServer.Models;

using Microsoft.AspNetCore.RateLimiting;

// レート制限 (SEC-09)。クライアント IP ごとの固定ウィンドウで、資格情報を受け取る認可エンドポイントは厳しめ、
// トークン系エンドポイントは緩めの上限を適用する。上限超過は 429 + Retry-After で応答する。
// リバースプロキシ配下では ForwardedHeaders を構成しないと全要求が同じ IP に見える点に注意。
public static class RateLimitingExtensions
{
    public const string AuthenticationPolicy = "authentication";
    public const string TokenPolicy = "token";

    public static IServiceCollection AddAuthServerRateLimiting(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        var settings = configuration.GetSection("RateLimiting").Get<RateLimitingOptions>() ?? new RateLimitingOptions();

        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.OnRejected = OnRejectedAsync;
            options.AddPolicy(AuthenticationPolicy, context => CreatePartition(context, settings, settings.AuthenticationPermitLimit));
            options.AddPolicy(TokenPolicy, context => CreatePartition(context, settings, settings.TokenPermitLimit));
        });
        return services;
    }

    private static RateLimitPartition<string> CreatePartition(HttpContext context, RateLimitingOptions settings, int permitLimit)
    {
        if (!settings.Enabled || (permitLimit <= 0))
        {
            return RateLimitPartition.GetNoLimiter("disabled");
        }

        var key = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        return RateLimitPartition.GetFixedWindowLimiter(key, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = permitLimit,
            Window = TimeSpan.FromSeconds(Math.Max(1, settings.WindowSeconds)),
            QueueLimit = 0,
            AutoReplenishment = true
        });
    }

    private static async ValueTask OnRejectedAsync(OnRejectedContext context, CancellationToken cancellationToken)
    {
        var httpContext = context.HttpContext;
        var retryAfterSeconds = context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter)
            ? Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds))
            : 1;

        httpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        httpContext.Response.Headers.RetryAfter = retryAfterSeconds.ToString(CultureInfo.InvariantCulture);

        var logger = httpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("RateLimiting");
        if (logger.IsEnabled(LogLevel.Warning))
        {
            logger.LogWarning(
                "Rate limit exceeded: {Method} {Path} from {RemoteIp}",
                httpContext.Request.Method, httpContext.Request.Path, httpContext.Connection.RemoteIpAddress);
        }

        await httpContext.Response.WriteAsJsonAsync(
            new
            {
                error = "temporarily_unavailable",
                error_description = $"Too many requests. Retry after {retryAfterSeconds} second(s)."
            },
            cancellationToken);
    }
}
