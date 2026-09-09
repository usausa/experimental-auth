namespace AuthServer.Security;

using AuthServer.Models;

// CORS (SEC-10)。Discovery / JWKS は公開メタデータなので任意オリジンの GET を許可し、
// プロトコルエンドポイントは Cors:AllowedOrigins に列挙したオリジンだけを許可する (未設定なら CORS 応答ヘッダーを返さない)。
public static class CorsExtensions
{
    public const string PublicMetadataPolicy = "public-metadata";
    public const string ApiPolicy = "api";

    public static IServiceCollection AddAuthServerCors(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        var settings = configuration.GetSection("Cors").Get<CorsSettings>() ?? new CorsSettings();
        var origins = settings.AllowedOrigins
            .Where(o => !String.IsNullOrWhiteSpace(o))
            .Select(o => o.Trim().TrimEnd('/'))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        services.AddCors(options =>
        {
            options.AddPolicy(PublicMetadataPolicy, policy => policy
                .AllowAnyOrigin()
                .WithMethods("GET")
                .WithHeaders("Accept", "Content-Type"));

            options.AddPolicy(ApiPolicy, policy =>
            {
                if (origins.Length > 0)
                {
                    policy.WithOrigins(origins)
                        .WithMethods("GET", "POST")
                        .WithHeaders("Authorization", "Content-Type", "Accept");
                }
            });
        });
        return services;
    }
}
