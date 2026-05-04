namespace ResourceServer.Endpoints;

using System.Security.Claims;

public static class ProtectedEndpoint
{
    public static void MapProtectedEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api");

        group.MapGet("/protected", HandleProtected)
            .RequireAuthorization("api.read");

        group.MapGet("/protected/admin", HandleAdmin)
            .RequireAuthorization("api.write");
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
