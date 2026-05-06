namespace AuthServer.Services;

using System.Globalization;
using AuthServer.Database;
using AuthServer.Models;
using Dapper;

public sealed class ResourceServerService(DbConnectionFactory dbFactory)
{
    private const string SelectColumns = """
        resource_server_id AS ResourceServerId,
        name               AS Name,
        audience           AS Audience,
        description        AS Description,
        is_active          AS IsActive,
        created_at         AS CreatedAt,
        updated_at         AS UpdatedAt
        """;

    public async Task<IReadOnlyList<ResourceServer>> GetAllAsync()
    {
        await using var connection = dbFactory.OpenConnection();
        var rows = await connection.QueryAsync<ResourceServer>(
            $"SELECT {SelectColumns} FROM resource_servers ORDER BY name");
        return rows.ToList();
    }

    public async Task<IReadOnlyList<ResourceServer>> GetActiveAsync()
    {
        await using var connection = dbFactory.OpenConnection();
        var rows = await connection.QueryAsync<ResourceServer>(
            $"SELECT {SelectColumns} FROM resource_servers WHERE is_active = 1 ORDER BY name");
        return rows.ToList();
    }

    public async Task<ResourceServer?> FindByIdAsync(string id)
    {
        await using var connection = dbFactory.OpenConnection();
        return await connection.QueryFirstOrDefaultAsync<ResourceServer>(
            $"SELECT {SelectColumns} FROM resource_servers WHERE resource_server_id = @Id",
            new { Id = id });
    }

    public async Task<bool> AudienceExistsAsync(string audience, string? excludeId = null)
    {
        await using var connection = dbFactory.OpenConnection();
        var count = await connection.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM resource_servers WHERE audience = @Audience AND (@ExcludeId IS NULL OR resource_server_id <> @ExcludeId)",
            new { Audience = audience, ExcludeId = excludeId });
        return count > 0;
    }

    public async Task CreateAsync(ResourceServer server)
    {
        ArgumentNullException.ThrowIfNull(server);
        var now = DateTime.UtcNow;
        server.ResourceServerId = string.IsNullOrEmpty(server.ResourceServerId)
            ? Guid.NewGuid().ToString("N")[..16]
            : server.ResourceServerId;
        server.CreatedAt = now;
        server.UpdatedAt = now;
        var nowStr = now.ToString("o", CultureInfo.InvariantCulture);

        await using var connection = dbFactory.OpenConnection();
        await connection.ExecuteAsync("""
            INSERT INTO resource_servers
                (resource_server_id, name, audience, description, is_active, created_at, updated_at)
            VALUES
                (@ResourceServerId, @Name, @Audience, @Description, @IsActive, @CreatedAt, @UpdatedAt)
            """,
            new
            {
                server.ResourceServerId,
                server.Name,
                server.Audience,
                server.Description,
                IsActive = server.IsActive ? 1 : 0,
                CreatedAt = nowStr,
                UpdatedAt = nowStr
            });
    }

    public async Task UpdateAsync(ResourceServer server)
    {
        ArgumentNullException.ThrowIfNull(server);
        var now = DateTime.UtcNow;
        server.UpdatedAt = now;
        var nowStr = now.ToString("o", CultureInfo.InvariantCulture);

        await using var connection = dbFactory.OpenConnection();
        await connection.ExecuteAsync("""
            UPDATE resource_servers
            SET name        = @Name,
                audience    = @Audience,
                description = @Description,
                is_active   = @IsActive,
                updated_at  = @UpdatedAt
            WHERE resource_server_id = @ResourceServerId
            """,
            new
            {
                server.ResourceServerId,
                server.Name,
                server.Audience,
                server.Description,
                IsActive = server.IsActive ? 1 : 0,
                UpdatedAt = nowStr
            });
    }

    public async Task DeleteAsync(string id)
    {
        await using var connection = dbFactory.OpenConnection();
        await connection.ExecuteAsync(
            "DELETE FROM resource_servers WHERE resource_server_id = @Id",
            new { Id = id });
    }
}
