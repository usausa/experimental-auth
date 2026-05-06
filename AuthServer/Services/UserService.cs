namespace AuthServer.Services;

using System.Globalization;

using AuthServer.Database;
using AuthServer.Models;

using Dapper;

public sealed class UserService(DbConnectionFactory dbFactory)
{
    private const string SelectColumns = """
        user_id            AS UserId,
        resource_server_id AS ResourceServerId,
        username           AS Username,
        password_hash      AS PasswordHash,
        email              AS Email,
        email_verified     AS EmailVerified,
        name               AS Name,
        given_name         AS GivenName,
        family_name        AS FamilyName,
        is_active          AS IsActive,
        created_at         AS CreatedAt,
        updated_at         AS UpdatedAt
        """;

    public async Task<IReadOnlyList<User>> GetAllAsync()
    {
        await using var connection = dbFactory.OpenConnection();
        var rows = await connection.QueryAsync<User>(
            $"SELECT {SelectColumns} FROM users ORDER BY username");
        return rows.ToList();
    }

    public async Task<IReadOnlyList<User>> GetByResourceServerAsync(string resourceServerId)
    {
        await using var connection = dbFactory.OpenConnection();
        var rows = await connection.QueryAsync<User>(
            $"SELECT {SelectColumns} FROM users WHERE resource_server_id = @ResourceServerId ORDER BY username",
            new { ResourceServerId = resourceServerId });
        return rows.ToList();
    }

    public async Task<User?> FindByIdAsync(string userId)
    {
        await using var connection = dbFactory.OpenConnection();
        return await connection.QueryFirstOrDefaultAsync<User>(
            $"SELECT {SelectColumns} FROM users WHERE user_id = @UserId",
            new { UserId = userId });
    }

    public async Task<User?> FindByUsernameAsync(string username)
    {
        await using var connection = dbFactory.OpenConnection();
        return await connection.QueryFirstOrDefaultAsync<User>(
            $"SELECT {SelectColumns} FROM users WHERE username = @Username",
            new { Username = username });
    }

    public async Task CreateAsync(User user, string plainPassword)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(plainPassword);

        var now = DateTime.UtcNow;
        user.UserId = string.IsNullOrEmpty(user.UserId) ? Guid.NewGuid().ToString("N")[..16] : user.UserId;
        user.PasswordHash = PasswordHasher.Hash(plainPassword);
        user.CreatedAt = now;
        user.UpdatedAt = now;

        var nowStr = now.ToString("o", CultureInfo.InvariantCulture);
        await using var connection = dbFactory.OpenConnection();
        await connection.ExecuteAsync("""
            INSERT INTO users
                (user_id, resource_server_id, username, password_hash, email, email_verified, name, given_name, family_name,
                 is_active, created_at, updated_at)
            VALUES
                (@UserId, @ResourceServerId, @Username, @PasswordHash, @Email, @EmailVerified, @Name, @GivenName, @FamilyName,
                 @IsActive, @CreatedAt, @UpdatedAt)
            """,
            new
            {
                user.UserId,
                user.ResourceServerId,
                user.Username,
                user.PasswordHash,
                user.Email,
                EmailVerified = user.EmailVerified ? 1 : 0,
                user.Name,
                user.GivenName,
                user.FamilyName,
                IsActive = user.IsActive ? 1 : 0,
                CreatedAt = nowStr,
                UpdatedAt = nowStr
            });
    }

    public async Task UpdateAsync(User user)
    {
        ArgumentNullException.ThrowIfNull(user);

        var now = DateTime.UtcNow;
        user.UpdatedAt = now;
        var nowStr = now.ToString("o", CultureInfo.InvariantCulture);

        await using var connection = dbFactory.OpenConnection();
        await connection.ExecuteAsync("""
            UPDATE users
            SET resource_server_id = @ResourceServerId,
                username       = @Username,
                email          = @Email,
                email_verified = @EmailVerified,
                name           = @Name,
                given_name     = @GivenName,
                family_name    = @FamilyName,
                is_active      = @IsActive,
                updated_at     = @UpdatedAt
            WHERE user_id = @UserId
            """,
            new
            {
                user.UserId,
                user.ResourceServerId,
                user.Username,
                user.Email,
                EmailVerified = user.EmailVerified ? 1 : 0,
                user.Name,
                user.GivenName,
                user.FamilyName,
                IsActive = user.IsActive ? 1 : 0,
                UpdatedAt = nowStr
            });
    }

    public async Task ChangePasswordAsync(string userId, string newPassword)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);
        ArgumentException.ThrowIfNullOrWhiteSpace(newPassword);

        var hash = PasswordHasher.Hash(newPassword);
        var nowStr = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
        await using var connection = dbFactory.OpenConnection();
        await connection.ExecuteAsync("""
            UPDATE users SET password_hash = @Hash, updated_at = @UpdatedAt WHERE user_id = @UserId
            """,
            new { Hash = hash, UpdatedAt = nowStr, UserId = userId });
    }

    public async Task DeleteAsync(string userId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);
        await using var connection = dbFactory.OpenConnection();
        await connection.ExecuteAsync("DELETE FROM users WHERE user_id = @UserId", new { UserId = userId });
    }

    public async Task<bool> UsernameExistsAsync(string username, string? excludeUserId = null)
    {
        await using var connection = dbFactory.OpenConnection();
        var count = await connection.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM users WHERE username = @Username AND (@ExcludeId IS NULL OR user_id != @ExcludeId)",
            new { Username = username, ExcludeId = excludeUserId });
        return count > 0;
    }
}
