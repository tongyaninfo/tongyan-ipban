using IpBan.Agent.Data;
using IpBan.Agent.Options;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace IpBan.Agent.Service.impl;

public sealed class SqliteDatabaseInitializer(
    IOptions<AgentOptions> options,
    IHostEnvironment environment) : IDatabaseInitializer
{
    public string DatabasePath { get; } = DatabasePathResolver.Resolve(options.Value, environment.ContentRootPath);

    public async Task<DatabaseInitializationResult> InitializeAsync(CancellationToken cancellationToken = default)
    {
        var directory = Path.GetDirectoryName(DatabasePath)
            ?? throw new InvalidOperationException("无法解析 SQLite 数据目录。");
        Directory.CreateDirectory(directory);

        var existed = File.Exists(DatabasePath);
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await ConfigureConnectionAsync(connection, cancellationToken).ConfigureAwait(false);

        // 使用 immediate transaction 抢占 SQLite 写锁，避免两个 Agent 进程同时首次迁移。
        using var transaction = connection.BeginTransaction(deferred: false);
        var previousVersion = await ReadCurrentVersionAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
        if (previousVersion > SqliteDatabaseSchema.CurrentVersion)
        {
            transaction.Rollback();
            throw new InvalidOperationException(
                $"数据库版本 {previousVersion} 高于程序支持的版本 {SqliteDatabaseSchema.CurrentVersion}，已停止启动。 ");
        }

        string? backupPath = null;
        if (existed && previousVersion < SqliteDatabaseSchema.CurrentVersion)
        {
            backupPath = CreateBackup();
        }

        if (previousVersion == SqliteDatabaseSchema.CurrentVersion)
        {
            transaction.Commit();
            return new DatabaseInitializationResult(
                DatabasePath,
                previousVersion,
                previousVersion,
                DatabaseCreated: !existed,
                backupPath);
        }

        try
        {
            await ExecuteNonQueryAsync(
                connection,
                "CREATE TABLE IF NOT EXISTS ipban_schema_migrations (version INTEGER NOT NULL PRIMARY KEY, applied_at_utc TEXT NOT NULL);",
                transaction,
                cancellationToken).ConfigureAwait(false);

            for (var version = previousVersion + 1; version <= SqliteDatabaseSchema.CurrentVersion; version++)
            {
                foreach (var statement in SqliteDatabaseSchema.GetMigrationStatements(version))
                {
                    await ExecuteNonQueryAsync(connection, statement, transaction, cancellationToken).ConfigureAwait(false);
                }

                await ExecuteNonQueryAsync(
                    connection,
                    "INSERT INTO ipban_schema_migrations(version, applied_at_utc) VALUES ($version, $appliedAtUtc);",
                    transaction,
                    cancellationToken,
                    ("$version", version),
                    ("$appliedAtUtc", DateTimeOffset.UtcNow.ToString("O"))).ConfigureAwait(false);
            }

            transaction.Commit();
        }
        catch
        {
            transaction.Rollback();
            throw;
        }

        return new DatabaseInitializationResult(
            DatabasePath,
            previousVersion,
            SqliteDatabaseSchema.CurrentVersion,
            DatabaseCreated: !existed,
            backupPath);
    }

    internal static async Task ConfigureConnectionAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        await using (var pragma = connection.CreateCommand())
        {
            pragma.CommandText = "PRAGMA busy_timeout = 10000; PRAGMA foreign_keys = ON;";
            await pragma.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        await using var journalMode = connection.CreateCommand();
        journalMode.CommandText = "PRAGMA journal_mode = WAL;";
        await journalMode.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
    }

    private SqliteConnection CreateConnection()
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

    private static async Task<int> ReadCurrentVersionAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var existsCommand = connection.CreateCommand();
        existsCommand.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'ipban_schema_migrations';";
        existsCommand.Transaction = transaction;
        var exists = Convert.ToInt32(await existsCommand.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false));
        if (exists == 0)
        {
            return 0;
        }

        await using var versionCommand = connection.CreateCommand();
        versionCommand.CommandText = "SELECT COALESCE(MAX(version), 0) FROM ipban_schema_migrations;";
        versionCommand.Transaction = transaction;
        return Convert.ToInt32(await versionCommand.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false));
    }

    private string CreateBackup()
    {
        var backupPath = $"{DatabasePath}.backup-{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}";
        // 迁移连接已经持有写锁。独立的只读连接可读取已提交的 WAL，使用 SQLite 备份保证快照一致。
        using var source = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private,
            Pooling = false
        }.ToString());
        source.Open();
        var backupOptions = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows())
        {
            backupOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }
        using (new FileStream(backupPath, backupOptions))
        {
        }
        using var destination = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = backupPath,
            Mode = SqliteOpenMode.ReadWrite,
            Pooling = false
        }.ToString());
        destination.Open();
        source.BackupDatabase(destination);
        return backupPath;
    }

    private static async Task ExecuteNonQueryAsync(
        SqliteConnection connection,
        string sql,
        SqliteTransaction transaction,
        CancellationToken cancellationToken,
        params (string Name, object Value)[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.Transaction = transaction;
        foreach (var (name, value) in parameters)
        {
            command.Parameters.AddWithValue(name, value);
        }

        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }
}
