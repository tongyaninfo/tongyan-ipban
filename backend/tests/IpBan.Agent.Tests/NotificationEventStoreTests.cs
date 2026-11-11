using System.Globalization;
using System.Text.Json;
using IpBan.Agent.Data;
using IpBan.Agent.Models;
using IpBan.Agent.Options;
using IpBan.Agent.Service;
using IpBan.Agent.Service.impl;
using IpBan.Shared.Logging;
using IpBan.Shared.Logging.Syslog;
using IpBan.Shared.Models;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace IpBan.Agent.Tests;

/// <summary>只使用隔离 SQLite 和假防火墙，验证通知不会把历史重放当作新登录。</summary>
public sealed class NotificationEventStoreTests
{
    [Fact]
    public async Task HostLoginSuccessUsesNoticeAndFailureUsesEmergency()
    {
        var fixture = await Fixture.CreateAsync();
        var directory = Path.GetDirectoryName(fixture.Factory.DatabasePath)!;
        var options = new FileLoggingOptions();
        using var fileLogger = new FileLoggerProvider(options, directory);
        var services = new ServiceCollection();
        services.AddSingleton(fileLogger);
        services.AddLogging(logging => services.AddIpBanSyslog(logging, "agent", directory, "test-host"));
        await using var provider = services.BuildServiceProvider();
        var logins = new SqliteLoginEventStore(fixture.Factory, provider.GetRequiredService<SyslogRuntime>());

        await logins.AppendAsync(Login(1, DateTimeOffset.UtcNow, success: true));
        await logins.AppendAsync(Login(2, DateTimeOffset.UtcNow));

        var logs = new FileLogStore(options, directory, fileLogger);
        var success = Assert.Single(logs.ReadLines(null, null, severity: 5, appName: "ipban-login"));
        var failure = Assert.Single(logs.ReadLines(null, null, severity: 0, appName: "ipban-login"));
        Assert.Contains("host.login.success", success, StringComparison.Ordinal);
        Assert.Contains("host.login.failure", failure, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DisabledNotificationsKeepLoginEvidenceWithoutCandidates()
    {
        var fixture = await Fixture.CreateAsync();
        await fixture.Logins.AppendAsync(Login(1, DateTimeOffset.UtcNow));
        await fixture.SetSettingsAsync(EnabledSettings() with { Enabled = false });
        await fixture.Logins.AppendAsync(Login(2, DateTimeOffset.UtcNow));

        Assert.Equal(2, await fixture.CountAsync("login_events"));
        Assert.Equal(0, await fixture.CountAsync("notification_events"));
    }

    [Fact]
    public async Task OnlyNewEnabledEventsProduceCandidatesAndReplayDoesNotDuplicate()
    {
        var fixture = await Fixture.CreateAsync();
        var enabledSince = DateTimeOffset.UtcNow.AddMinutes(-1);
        await fixture.SetSettingsAsync(EnabledSettings() with { EnabledSinceUtc = enabledSince });
        await fixture.Logins.AppendAsync(Login(1, enabledSince.AddSeconds(-1)));
        await fixture.Logins.AppendAsync(Login(2, enabledSince));
        var recent = Login(3, enabledSince.AddSeconds(1));
        await fixture.Logins.AppendAsync(recent);
        await fixture.Logins.AppendAsync(recent with { Id = 4 });

        var snapshot = Assert.Single(await fixture.ReadSnapshotsAsync());
        Assert.Equal("3", snapshot.SourceId);
        Assert.Equal("loginFailure", snapshot.EventType);
        Assert.Equal("Failure", snapshot.Status);
        Assert.Equal(3, await fixture.CountAsync("login_events"));
    }

    [Fact]
    public async Task PerTypeSwitchAndMaximumAgeFilterCandidates()
    {
        var fixture = await Fixture.CreateAsync();
        var settings = EnabledSettings() with
        {
            EnabledSinceUtc = DateTimeOffset.UtcNow.AddDays(-3),
            Rules = [new("loginSuccess", false, 300), new("loginFailure", true, 600)]
        };
        await fixture.SetSettingsAsync(settings);
        await fixture.Logins.AppendAsync(Login(1, DateTimeOffset.UtcNow, success: true));
        await fixture.Logins.AppendAsync(Login(2, DateTimeOffset.UtcNow.AddHours(-25)));
        await fixture.Logins.AppendAsync(Login(3, DateTimeOffset.UtcNow));

        Assert.Equal("3", Assert.Single(await fixture.ReadSnapshotsAsync()).SourceId);
        Assert.Equal(3, await fixture.CountAsync("login_events"));
    }

    [Fact]
    public async Task SuccessGroupingNormalizesMappedAddressAndBoundsUntrustedUsername()
    {
        var fixture = await Fixture.CreateAsync();
        await fixture.SetSettingsAsync(EnabledSettings());
        await fixture.Logins.AppendAsync(Login(1, DateTimeOffset.UtcNow, success: true) with
        {
            RemoteIp = "::ffff:192.0.2.10", LocalIp = "::ffff:198.51.100.20", Username = new string('x', 600)
        });

        var snapshot = Assert.Single(await fixture.ReadSnapshotsAsync());
        Assert.Equal("Success", snapshot.Status);
        Assert.Equal("192.0.2.10", snapshot.SourceIp);
        Assert.Equal("198.51.100.20", snapshot.LocalIp);
        Assert.Equal(256, snapshot.Username!.Length);
        await using var connection = await fixture.Factory.OpenConnectionAsync();
        await using var query = connection.CreateCommand();
        query.CommandText = "SELECT group_key FROM notification_events;";
        Assert.Equal($"loginSuccess|192.0.2.10|Ssh|{new string('x', 256)}", await query.ExecuteScalarAsync());
    }

    [Theory]
    [InlineData("{invalid-json")]
    [InlineData("{\"enabled\":true,\"rules\":null}")]
    public async Task InvalidOrIncompleteNotificationSettingsDoNotBlockEvidence(string json)
    {
        var fixture = await Fixture.CreateAsync();
        await fixture.SetRawSettingsAsync(json);
        await fixture.Logins.AppendAsync(Login(1, DateTimeOffset.UtcNow));
        Assert.Equal(1, await fixture.CountAsync("login_events"));
        Assert.Equal(0, await fixture.CountAsync("notification_events"));
    }

    [Fact]
    public async Task FullCandidateQueueKeepsSourceEventAndUsesOneOverflowCounter()
    {
        var fixture = await Fixture.CreateAsync();
        await fixture.SetSettingsAsync(EnabledSettings());
        await using (var connection = await fixture.Factory.OpenConnectionAsync())
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "WITH RECURSIVE numbers(value) AS (SELECT 1 UNION ALL SELECT value+1 FROM numbers WHERE value<10000) INSERT INTO notification_events(event_key,event_type,group_key,payload_json,config_revision,occurred_at_utc,created_at_utc) SELECT 'fixture:'||value,'loginFailure','fixture','{}','v1',$now,$now FROM numbers;";
            command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
            await command.ExecuteNonQueryAsync();
        }
        await fixture.Logins.AppendAsync(Login(1, DateTimeOffset.UtcNow));
        await fixture.Logins.AppendAsync(Login(2, DateTimeOffset.UtcNow) with { RemoteIp = "192.0.2.11" });

        Assert.Equal(2, await fixture.CountAsync("login_events"));
        Assert.Equal(10000, await fixture.CountAsync("notification_events"));
        Assert.Equal(1, await fixture.CountAsync("notification_rate_state"));
        await using var verify = await fixture.Factory.OpenConnectionAsync();
        await using var count = verify.CreateCommand();
        count.CommandText = "SELECT suppressed_count FROM notification_rate_state WHERE state_key='candidate:overflow:loginFailure';";
        Assert.Equal(2L, await count.ExecuteScalarAsync());
    }

    [Theory]
    [InlineData(FirewallActionStatus.Applied)]
    [InlineData(FirewallActionStatus.Disabled)]
    [InlineData(FirewallActionStatus.Failed)]
    public async Task BanCandidateKeepsRealOutcomeAndCallerContext(FirewallActionStatus status)
    {
        var fixture = await Fixture.CreateAsync();
        await fixture.SetSettingsAsync(EnabledSettings());
        var result = new FirewallActionResult("synthetic", "192.0.2.10", status,
            status == FirewallActionStatus.Disabled ? FirewallStatus.Disabled : FirewallStatus.Enabled,
            status == FirewallActionStatus.Applied ? null : "TEST_FAILURE", "raw diagnostics must not enter email", DateTimeOffset.UtcNow);
        var id = await fixture.Actions.AppendAsync("auto-ban", result,
            new FirewallNotificationContext("合成策略达到阈值", 300, Protocol: "Ssh"));

        var snapshot = Assert.Single(await fixture.ReadSnapshotsAsync());
        Assert.Equal("ban", snapshot.EventType);
        Assert.Equal(status.ToString(), snapshot.Status);
        Assert.Equal("auto-ban", snapshot.Action);
        Assert.Equal(id.ToString(CultureInfo.InvariantCulture), snapshot.SourceId);
        Assert.Equal("合成策略达到阈值", snapshot.Reason);
        Assert.Equal(300, snapshot.DurationSeconds);
        Assert.Equal("synthetic", snapshot.Provider);
    }

    [Fact]
    public async Task LoginStormPreservesCandidateSpaceForBanAndUnban()
    {
        var fixture = await Fixture.CreateAsync();
        await fixture.SetSettingsAsync(EnabledSettings());
        await using (var connection = await fixture.Factory.OpenConnectionAsync())
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "WITH RECURSIVE numbers(value) AS (SELECT 1 UNION ALL SELECT value+1 FROM numbers WHERE value<8000) INSERT INTO notification_events(event_key,event_type,group_key,payload_json,config_revision,occurred_at_utc,created_at_utc) SELECT 'fixture:'||value,'loginFailure','fixture','{}','v1',$now,$now FROM numbers;";
            command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
            await command.ExecuteNonQueryAsync();
        }

        await fixture.Logins.AppendAsync(Login(1, DateTimeOffset.UtcNow));
        var ban = await fixture.Actions.AppendAsync("ban", new("synthetic", "192.0.2.10", FirewallActionStatus.Applied,
            FirewallStatus.Enabled, null, null, DateTimeOffset.UtcNow));
        await fixture.Actions.AppendAsync("manual-unban", new("synthetic", "192.0.2.10", FirewallActionStatus.Removed,
            FirewallStatus.Enabled, null, null, DateTimeOffset.UtcNow), new FirewallNotificationContext(OriginalActionId: ban));

        Assert.Equal(1, await fixture.CountAsync("login_events"));
        Assert.Equal(2, await fixture.CountAsync("firewall_actions"));
        Assert.Equal(8002, await fixture.CountAsync("notification_events"));
        await using var verify = await fixture.Factory.OpenConnectionAsync();
        await using var count = verify.CreateCommand();
        count.CommandText = "SELECT COUNT(*) FROM notification_events WHERE event_type IN ('ban','unban') AND priority=1;";
        Assert.Equal(2L, await count.ExecuteScalarAsync());
        count.CommandText = "SELECT suppressed_count FROM notification_rate_state WHERE state_key='candidate:overflow:loginFailure';";
        Assert.Equal(1L, await count.ExecuteScalarAsync());
    }

    [Fact]
    public async Task ManualAndExpiryUnbanSnapshotsReferToCurrentBanOnly()
    {
        var fixture = await Fixture.CreateAsync();
        await fixture.SetSettingsAsync(EnabledSettings());
        var provider = new SyntheticFirewall();
        using var coordinator = new FirewallActionCoordinator(fixture.Factory, fixture.Actions, [provider]);
        var first = await coordinator.BanAsync(provider, "192.0.2.10", "ban", CancellationToken.None,
            notificationContext: new FirewallNotificationContext("人工封禁", 300));
        Assert.True((await coordinator.UnbanAsync(first.Id, "192.0.2.10", CancellationToken.None)).Success);
        Assert.Null(await coordinator.ExpireAsync(provider, "192.0.2.10", first.Id, "unban", CancellationToken.None));
        var second = await coordinator.BanAsync(provider, "192.0.2.10", "ban", CancellationToken.None);
        await coordinator.ExpireAsync(provider, "192.0.2.10", second.Id, "unban", CancellationToken.None);

        var snapshots = await fixture.ReadSnapshotsAsync();
        Assert.Equal(4, snapshots.Length);
        var manual = Assert.Single(snapshots, item => item.Action == "manual-unban");
        Assert.Equal("Removed", manual.Status);
        Assert.Equal(first.Id.ToString(CultureInfo.InvariantCulture), manual.OriginalActionId);
        var expiry = Assert.Single(snapshots, item => item.Action == "unban");
        Assert.Equal("Removed", expiry.Status);
        Assert.Equal(second.Id.ToString(CultureInfo.InvariantCulture), expiry.OriginalActionId);
    }

    [Fact]
    public async Task MigrationFromV6PreservesExistingDataAndCreatesNotificationTables()
    {
        var fixture = await Fixture.CreateAsync(previousVersion: 6);
        Assert.Equal(7, SqliteDatabaseSchema.CurrentVersion);
        Assert.Equal(0, await fixture.CountAsync("notification_events"));
        Assert.Equal(0, await fixture.CountAsync("notification_outbox"));
        Assert.Equal(0, await fixture.CountAsync("notification_rate_state"));
        await using var connection = await fixture.Factory.OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT setting_value FROM system_settings WHERE setting_key='preserved';";
        Assert.Equal("existing-v6-data", await command.ExecuteScalarAsync());
    }

    private static NotificationSettings EnabledSettings() => new()
    {
        Enabled = true, EnabledSinceUtc = DateTimeOffset.UtcNow.AddMinutes(-5), Revision = "notification-test-v1"
    };

    private static LoginEventContract Login(long id, DateTimeOffset occurred, bool success = false) => new(
        id, occurred, ProtocolKind.Ssh, success, "synthetic-user", "192.0.2.10", 42000, "192.0.2.20", 22,
        42, "sshd", null, null, EventCompletenessLevel.IpEnforceable,
        FieldAvailability.Available, FieldAvailability.Available, FieldAvailability.Available,
        FieldAvailability.Available, "synthetic-notification", $"event-{id}", "synthetic");

    private sealed record Fixture(SqliteConnectionFactory Factory)
    {
        public SqliteLoginEventStore Logins => new(Factory);
        public SqliteFirewallActionStore Actions => new(Factory);

        public static async Task<Fixture> CreateAsync(int? previousVersion = null)
        {
            var directory = Path.Combine(Path.GetTempPath(), "ipban-notification-tests", Guid.NewGuid().ToString("N"));
            var options = Microsoft.Extensions.Options.Options.Create(new AgentOptions { DataDirectory = directory, DatabaseFileName = "test.sqlite3" });
            var environment = new TestEnvironment(directory);
            var initializer = new SqliteDatabaseInitializer(options, environment);
            if (previousVersion is { } version)
            {
                Directory.CreateDirectory(directory);
                await using var existing = new SqliteConnection($"Data Source={initializer.DatabasePath}");
                await existing.OpenAsync();
                await using var command = existing.CreateCommand();
                command.CommandText = "CREATE TABLE ipban_schema_migrations(version INTEGER PRIMARY KEY,applied_at_utc TEXT NOT NULL);";
                await command.ExecuteNonQueryAsync();
                for (var current = 1; current <= version; current++)
                {
                    foreach (var statement in SqliteDatabaseSchema.GetMigrationStatements(current))
                    {
                        command.CommandText = statement;
                        await command.ExecuteNonQueryAsync();
                    }
                    command.CommandText = "INSERT INTO ipban_schema_migrations VALUES($version,'2026-01-01T00:00:00Z');";
                    command.Parameters.Clear();
                    command.Parameters.AddWithValue("$version", current);
                    await command.ExecuteNonQueryAsync();
                }
                command.Parameters.Clear();
                command.CommandText = "INSERT INTO system_settings VALUES('preserved','existing-v6-data',0,'2026-01-01T00:00:00Z',NULL);";
                await command.ExecuteNonQueryAsync();
            }
            await initializer.InitializeAsync();
            return new Fixture(new SqliteConnectionFactory(options, environment));
        }

        public Task SetSettingsAsync(NotificationSettings settings) =>
            SetRawSettingsAsync(JsonSerializer.Serialize(settings, NotificationJsonContext.Default.NotificationSettings));

        public async Task SetRawSettingsAsync(string json)
        {
            await using var connection = await Factory.OpenConnectionAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "INSERT INTO system_settings VALUES('notifications.settings',$json,0,$now,NULL) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value;";
            command.Parameters.AddWithValue("$json", json);
            command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
            await command.ExecuteNonQueryAsync();
        }

        public async Task<long> CountAsync(string table)
        {
            await using var connection = await Factory.OpenConnectionAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = $"SELECT COUNT(*) FROM {table};";
            return Convert.ToInt64(await command.ExecuteScalarAsync(), CultureInfo.InvariantCulture);
        }

        public async Task<NotificationEventSnapshot[]> ReadSnapshotsAsync()
        {
            await using var connection = await Factory.OpenConnectionAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT payload_json FROM notification_events ORDER BY event_key;";
            await using var reader = await command.ExecuteReaderAsync();
            var snapshots = new List<NotificationEventSnapshot>();
            while (await reader.ReadAsync())
                snapshots.Add(JsonSerializer.Deserialize(reader.GetString(0), NotificationJsonContext.Default.NotificationEventSnapshot)!);
            return snapshots.ToArray();
        }
    }

    private sealed class TestEnvironment(string directory) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Test";
        public string ApplicationName { get; set; } = "IpBan.Agent.Tests";
        public string ContentRootPath { get; set; } = directory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    private sealed class SyntheticFirewall : IFirewallProvider
    {
        public string Name => "synthetic";
        public string Platform => "synthetic";
        public FirewallCapabilities Capabilities => new(Name, Platform, true, true, true, false, false);
        public Task<FirewallObservation> DetectAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(new FirewallObservation(Name, FirewallStatus.Enabled, true, null, DateTimeOffset.UtcNow, Capabilities));
        public Task<FirewallActionResult> BanAsync(string sourceAddress, CancellationToken cancellationToken = default) =>
            Task.FromResult(new FirewallActionResult(Name, sourceAddress, FirewallActionStatus.Applied, FirewallStatus.Enabled, null, null, DateTimeOffset.UtcNow));
        public Task<FirewallActionResult> UnbanAsync(string sourceAddress, CancellationToken cancellationToken = default) =>
            Task.FromResult(new FirewallActionResult(Name, sourceAddress, FirewallActionStatus.Removed, FirewallStatus.Enabled, null, null, DateTimeOffset.UtcNow));
    }
}
