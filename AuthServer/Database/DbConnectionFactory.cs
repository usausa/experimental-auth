namespace AuthServer.Database;

using Microsoft.Data.Sqlite;

/// <summary>Creates SQLite connections to the AuthServer database.</summary>
public sealed class DbConnectionFactory
{
    private readonly string connectionString;

    public DbConnectionFactory(string dataDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDirectory);

        Directory.CreateDirectory(dataDirectory);
        var dbPath = Path.Combine(dataDirectory, "AuthServer.db");
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = dbPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared
        };
        connectionString = builder.ConnectionString;
    }

    public SqliteConnection OpenConnection()
    {
        var connection = new SqliteConnection(connectionString);
        connection.Open();
        return connection;
    }
}
