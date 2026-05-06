namespace ResourceServer.Endpoints;

using System.Security.Claims;

using Microsoft.OpenApi;

public static class ProtectedEndpoint
{
    private static readonly OpenApiSecurityRequirement BearerRequirement = new()
    {
        [new OpenApiSecuritySchemeReference("Bearer")] = []
    };

    public static void MapProtectedEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api").WithTags("Protected");

        group.MapGet("/protected", HandleProtected)
            .RequireAuthorization("api.read")
            .WithSummary("保護されたリソースの取得")
            .WithDescription("スコープ `api.read` を持つ有効な Bearer トークンが必要です。")
            .Produces<object>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .AddOpenApiOperationTransformer((op, _, _) =>
            {
                op.Security ??= [];
                op.Security.Add(BearerRequirement);
                return Task.CompletedTask;
            });

        group.MapGet("/protected/admin", HandleAdmin)
            .RequireAuthorization("api.write")
            .WithSummary("管理者専用リソースの取得")
            .WithDescription("スコープ `api.write` を持つ有効な Bearer トークンが必要です。")
            .Produces<object>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .AddOpenApiOperationTransformer((op, _, _) =>
            {
                op.Security ??= [];
                op.Security.Add(BearerRequirement);
                return Task.CompletedTask;
            });
    }

    private static IResult HandleProtected(ClaimsPrincipal user) =>
        Results.Ok(new
        {
            message = "Hello from the protected resource",
            subject = user.FindFirst("sub")?.Value,
            clientId = user.FindFirst("client_id")?.Value,
            scope = user.FindFirst("scope")?.Value,
            timestamp = DateTime.UtcNow
        });

    private static IResult HandleAdmin(ClaimsPrincipal user) =>
        Results.Ok(new
        {
            message = "Hello from the admin-only resource",
            clientId = user.FindFirst("client_id")?.Value
        });
}
