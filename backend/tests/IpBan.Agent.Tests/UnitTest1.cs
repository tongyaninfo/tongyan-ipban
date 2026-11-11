using IpBan.Agent.Data;
using IpBan.Agent.Options;
using IpBan.Agent.Service.impl;
using IpBan.Shared.Models;
using IpBan.Shared.Service;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace IpBan.Agent.Tests;

public sealed class AgentOptionsTests
{
    [Fact]
    public void DefaultsKeepStrictCompletenessDisabled()
    {
        var options = new AgentOptions();

        Assert.Equal("data", options.DataDirectory);
        Assert.False(options.StrictEventCompleteness);
    }

    [Fact]
    public void MissingWorkerIdIsRejected()
    {
        var options = new IdGenerationOptions();

        Assert.Throws<InvalidOperationException>(() => options.CreateGeneratorOptions());
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(IdGenerationOptions.MaxWorkerId + 1)]
    public void WorkerIdOutsideSixBitRangeIsRejected(int workerId)
    {
        var options = new IdGenerationOptions
        {
            WorkerId = workerId
        };

        Assert.Throws<InvalidOperationException>(() => options.CreateGeneratorOptions());
    }

    [Fact]
    public void ExplicitWorkerIdGeneratesIncreasingPositiveIds()
    {
        var options = Microsoft.Extensions.Options.Options.Create(new IdGenerationOptions
        {
            WorkerId = 3
        });
        var idService = new YiteIdService(options);
        Assert.IsAssignableFrom<IIdService>(idService);

        var first = idService.NewId;
        var second = idService.NewId;

        Assert.True(first > 0);
        Assert.True(second > first);
    }
}

public sealed class SqliteDatabaseInitializerTests
{
    [Fact]
    public async Task CreatesSchemaAndEnablesWal()
    {
        var dataDirectory = Path.Combine(Path.GetTempPath(), "ipban-tests", Guid.NewGuid().ToString("N"));
        var options = Microsoft.Extensions.Options.Options.Create(new AgentOptions
        {
            DataDirectory = dataDirectory,
            DatabaseFileName = "test.sqlite3"
        });
        var environment = new TestHostEnvironment(dataDirectory);
        var initializer = new SqliteDatabaseInitializer(options, environment);

        var result = await initializer.InitializeAsync();

        Assert.True(result.DatabaseCreated);
        Assert.Equal(0, result.PreviousVersion);
        Assert.Equal(SqliteDatabaseSchema.CurrentVersion, result.CurrentVersion);
        Assert.True(File.Exists(result.DatabasePath));

        await using var connection = new SqliteConnection($"Data Source={result.DatabasePath}");
        await connection.OpenAsync();
        await using var tableCommand = connection.CreateCommand();
        tableCommand.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('login_events', 'connection_snapshots', 'login_sessions', 'firewall_actions', 'users', 'user_sessions', 'system_settings', 'audit_records', 'certificate_metadata', 'backup_records', 'log_rotation_records', 'access_list_entries', 'ban_policies');";
        Assert.Equal(13L, await tableCommand.ExecuteScalarAsync());

        await using var journalCommand = connection.CreateCommand();
        journalCommand.CommandText = "PRAGMA journal_mode;";
        Assert.Equal("wal", Convert.ToString(await journalCommand.ExecuteScalarAsync(), System.Globalization.CultureInfo.InvariantCulture));
    }

    [Fact]
    public async Task SecondInitializationIsIdempotent()
    {
        var dataDirectory = Path.Combine(Path.GetTempPath(), "ipban-tests", Guid.NewGuid().ToString("N"));
        var options = Microsoft.Extensions.Options.Options.Create(new AgentOptions
        {
            DataDirectory = dataDirectory,
            DatabaseFileName = "test.sqlite3"
        });
        var environment = new TestHostEnvironment(dataDirectory);
        var initializer = new SqliteDatabaseInitializer(options, environment);

        var first = await initializer.InitializeAsync();
        var second = await initializer.InitializeAsync();

        Assert.Equal(SqliteDatabaseSchema.CurrentVersion, first.CurrentVersion);
        Assert.Equal(SqliteDatabaseSchema.CurrentVersion, second.CurrentVersion);
        Assert.Null(second.BackupPath);
    }

    [Fact]
    public async Task ExistingDatabaseCreatesPreMigrationBackup()
    {
        var dataDirectory = Path.Combine(Path.GetTempPath(), "ipban-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dataDirectory);
        var databasePath = Path.Combine(dataDirectory, "test.sqlite3");
        await using (var existing = new SqliteConnection($"Data Source={databasePath}"))
        {
            await existing.OpenAsync();
        }

        var options = Microsoft.Extensions.Options.Options.Create(new AgentOptions
        {
            DataDirectory = dataDirectory,
            DatabaseFileName = "test.sqlite3"
        });
        var initializer = new SqliteDatabaseInitializer(options, new TestHostEnvironment(dataDirectory));

        var result = await initializer.InitializeAsync();

        Assert.False(result.DatabaseCreated);
        Assert.NotNull(result.BackupPath);
        Assert.True(File.Exists(result.BackupPath));
    }

    [Fact]
    public async Task V6BackupIncludesCommittedWalBeforeAddingMcpTables()
    {
        var dataDirectory = Path.Combine(Path.GetTempPath(), "ipban-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dataDirectory);
        var options = Microsoft.Extensions.Options.Options.Create(new AgentOptions { DataDirectory = dataDirectory, DatabaseFileName = "test.sqlite3" });
        var initializer = new SqliteDatabaseInitializer(options, new TestHostEnvironment(dataDirectory));
        await using var previous = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = initializer.DatabasePath, Pooling = false
        }.ToString());
        await previous.OpenAsync();
        await using var command = previous.CreateCommand();
        command.CommandText = "PRAGMA journal_mode = WAL; PRAGMA wal_autocheckpoint = 0; CREATE TABLE ipban_schema_migrations(version INTEGER NOT NULL PRIMARY KEY, applied_at_utc TEXT NOT NULL);";
        await command.ExecuteNonQueryAsync();
        for (var version = 1; version <= 5; version++)
        {
            foreach (var statement in SqliteDatabaseSchema.GetMigrationStatements(version))
            {
                command.CommandText = statement;
                await command.ExecuteNonQueryAsync();
            }
            command.CommandText = "INSERT INTO ipban_schema_migrations VALUES ($version, '2026-01-01T00:00:00Z');";
            command.Parameters.Clear();
            command.Parameters.AddWithValue("$version", version);
            await command.ExecuteNonQueryAsync();
        }
        command.Parameters.Clear();
        command.CommandText = "INSERT INTO system_settings VALUES ('fixture', 'committed in WAL', 0, '2026-01-01T00:00:00Z', NULL);";
        await command.ExecuteNonQueryAsync();

        var result = await initializer.InitializeAsync();
        Assert.Equal(5, result.PreviousVersion);
        Assert.Equal(SqliteDatabaseSchema.CurrentVersion, result.CurrentVersion);
        Assert.NotNull(result.BackupPath);

        await using var backup = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = result.BackupPath, Mode = SqliteOpenMode.ReadOnly, Pooling = false
        }.ToString());
        await backup.OpenAsync();
        await using var snapshot = backup.CreateCommand();
        snapshot.CommandText = "SELECT setting_value FROM system_settings WHERE setting_key = 'fixture';";
        Assert.Equal("committed in WAL", await snapshot.ExecuteScalarAsync());
        snapshot.CommandText = "SELECT MAX(version) FROM ipban_schema_migrations;";
        Assert.Equal(5L, await snapshot.ExecuteScalarAsync());
        snapshot.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE name = 'mcp_settings';";
        Assert.Equal(0L, await snapshot.ExecuteScalarAsync());
        command.CommandText = "SELECT audit_retention_days FROM mcp_settings WHERE id = 1 AND enabled = 0;";
        Assert.Equal(30L, await command.ExecuteScalarAsync());
    }

    [Fact]
    public async Task ConcurrentInitializersShareOneMigrationResult()
    {
        var dataDirectory = Path.Combine(Path.GetTempPath(), "ipban-tests", Guid.NewGuid().ToString("N"));
        var options = Microsoft.Extensions.Options.Options.Create(new AgentOptions
        {
            DataDirectory = dataDirectory,
            DatabaseFileName = "test.sqlite3"
        });
        var environment = new TestHostEnvironment(dataDirectory);
        var first = new SqliteDatabaseInitializer(options, environment);
        var second = new SqliteDatabaseInitializer(options, environment);

        var results = await Task.WhenAll(first.InitializeAsync(), second.InitializeAsync());

        Assert.All(results, result => Assert.Equal(SqliteDatabaseSchema.CurrentVersion, result.CurrentVersion));
        await using var connection = new SqliteConnection($"Data Source={results[0].DatabasePath}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM ipban_schema_migrations;";
        Assert.Equal((long)SqliteDatabaseSchema.CurrentVersion, await command.ExecuteScalarAsync());
    }

    [Fact]
    public async Task EventStorePersistsIncompleteEventWithoutUnknownValues()
    {
        var dataDirectory = Path.Combine(Path.GetTempPath(), "ipban-tests", Guid.NewGuid().ToString("N"));
        var options = Microsoft.Extensions.Options.Options.Create(new AgentOptions
        {
            DataDirectory = dataDirectory,
            DatabaseFileName = "test.sqlite3"
        });
        var environment = new TestHostEnvironment(dataDirectory);
        var initializer = new SqliteDatabaseInitializer(options, environment);
        await initializer.InitializeAsync();

        var factory = new SqliteConnectionFactory(options, environment);
        var store = new SqliteLoginEventStore(factory);
        var loginEvent = new LoginEventContract(
            Id: 1001,
            OccurredAtUtc: DateTimeOffset.Parse("2026-01-01T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture),
            Protocol: ProtocolKind.Vnc,
            Success: false,
            Username: null,
            RemoteIp: null,
            RemotePort: null,
            LocalIp: "127.0.0.1",
            LocalPort: 5900,
            LocalProcessId: 42,
            LocalProcessName: "Xvnc",
            OriginProcessId: null,
            OriginProcessName: null,
            CompletenessLevel: EventCompletenessLevel.ObserveOnly,
            UsernameAvailability: FieldAvailability.NotProvided,
            RemoteIpAvailability: FieldAvailability.NotCollected,
            EndpointAvailability: FieldAvailability.Available,
            ProcessAvailability: FieldAvailability.CorrelationFailed,
            Collector: "test",
            RawEventId: "raw-1",
            EvidenceSource: "synthetic");

        await store.AppendAsync(loginEvent);
        var events = await store.QueryRecentAsync();

        var persisted = Assert.Single(events);
        Assert.Null(persisted.RemoteIp);
        Assert.Equal(FieldAvailability.NotCollected, persisted.RemoteIpAvailability);
        Assert.Equal(EventCompletenessLevel.ObserveOnly, persisted.CompletenessLevel);

        // 日志重读和 Agent 重启可重放同一证据，不能再次增加策略的失败次数。
        await store.AppendAsync(loginEvent with { Id = 1002 });
        Assert.Single(await store.QueryRecentAsync());

        // 同秒发生的独立认证，以及不同采集源的相同原始 ID，都必须保留。
        await store.AppendAsync(loginEvent with { Id = 1003, RawEventId = "raw-2" });
        await store.AppendAsync(loginEvent with { Id = 1004, Collector = "other-test" });
        await store.AppendAsync(loginEvent with { Id = 1005, RawEventId = null });
        await store.AppendAsync(loginEvent with { Id = 1006, RawEventId = null });
        Assert.Equal(5, (await store.QueryRecentAsync()).Count);
    }

    private sealed class TestHostEnvironment(string contentRootPath) : Microsoft.Extensions.Hosting.IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Test";
        public string ApplicationName { get; set; } = "IpBan.Agent.Tests";
        public string ContentRootPath { get; set; } = contentRootPath;
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = new Microsoft.Extensions.FileProviders.NullFileProvider();
    }
}
