using Microsoft.Data.Sqlite;

namespace IpBan.Agent.Service;

public interface ISqliteConnectionFactory
{
    string DatabasePath { get; }

    SqliteConnection CreateConnection();

    Task<SqliteConnection> OpenConnectionAsync(CancellationToken cancellationToken = default);
}
