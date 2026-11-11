using IpBan.Agent.Data;
using IpBan.Agent.Options;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace IpBan.Agent.Service.impl;

public sealed class SqliteConnectionFactory(
    IOptions<AgentOptions> options,
    IHostEnvironment environment) : ISqliteConnectionFactory
{
    public string DatabasePath { get; } = DatabasePathResolver.Resolve(options.Value, environment.ContentRootPath);

    public SqliteConnection CreateConnection()
    {
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = true,
            DefaultTimeout = 30
        }.ToString();

        return new SqliteConnection(connectionString);
    }

    public async Task<SqliteConnection> OpenConnectionAsync(CancellationToken cancellationToken = default)
    {
        var connection = CreateConnection();
        try
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await SqliteDatabaseInitializer.ConfigureConnectionAsync(connection, cancellationToken).ConfigureAwait(false);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }
}
