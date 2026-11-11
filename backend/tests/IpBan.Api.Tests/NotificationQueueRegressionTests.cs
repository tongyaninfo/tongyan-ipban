using System.Globalization;
using System.Text.Json;
using IpBan.Agent.Options;
using IpBan.Agent.Service.impl;
using IpBan.Api.Options;
using IpBan.Api.Service;
using IpBan.Api.Service.impl;
using IpBan.Shared.Models;
using IpBan.Shared.Service;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;

namespace IpBan.Api.Tests;

/// <summary>针对冷却队列饥饿、全局额度恢复和并发领取的回归；只使用隔离 SQLite 与假投递器。</summary>
public sealed class NotificationQueueRegressionTests
{
    [Fact]
    public async Task FiftyCoolingGroupsDoNotStarveANewSource()
    {
        using var fixture = await Fixture.CreateAsync();
        for (var index = 1; index <= 50; index++)
        {
            var source = $"192.0.2.{index}";
            await fixture.AddAsync($"cooling-{index}", source);
            await fixture.ExecuteAsync("INSERT INTO notification_rate_state(state_key,last_sent_at_utc,updated_at_utc) VALUES($key,$now,$now);",
                ("$key", $"group:{fixture.Settings.Revision}:loginFailure|{source}|Ssh"), ("$now", Utc(fixture.Clock.GetUtcNow())));
        }
        fixture.Clock.Advance(TimeSpan.FromSeconds(1));
        await fixture.AddAsync("new-source", "192.0.2.251");

        await fixture.Service.ProcessOnceAsync(CancellationToken.None);

        Assert.Single(fixture.Sender.Calls);
        var sent = Assert.Single((await fixture.Service.ListMessagesAsync(1, 100, "sent", null, CancellationToken.None)).Items);
        Assert.Equal("192.0.2.251", sent.SourceIp);
        Assert.Equal(50L, await fixture.CountAsync("SELECT COUNT(*) FROM notification_events WHERE status='pending';"));
    }

    [Fact]
    public async Task HourlyQuotaRecoveryDoesNotBurstMultipleWindowsOfTheSameSource()
    {
        using var fixture = await Fixture.CreateAsync(maxPerMinute: 5, maxPerHour: 5);
        // 实际发送四封登录通知与一封封禁通知，耗尽本小时额度（含预留额度）。
        for (var index = 1; index <= 4; index++)
        {
            await fixture.AddAsync($"quota-{index}", $"192.0.2.{index}");
            await fixture.Service.ProcessOnceAsync(CancellationToken.None);
        }
        await fixture.AddAsync("quota-ban", "192.0.2.5", "ban");
        await fixture.Service.ProcessOnceAsync(CancellationToken.None);
        Assert.Equal(5, fixture.Sender.Calls.Count);

        await fixture.AddAsync("blocked-first", "192.0.2.10");
        await fixture.Service.ProcessOnceAsync(CancellationToken.None);
        for (var index = 1; index <= 3; index++)
        {
            fixture.Clock.Advance(TimeSpan.FromMinutes(10));
            await fixture.AddAsync($"later-{index}", "192.0.2.10");
            await fixture.Service.ProcessOnceAsync(CancellationToken.None);
        }
        Assert.Equal(5, fixture.Sender.Calls.Count);
        Assert.Equal(1L, await fixture.CountAsync("SELECT COUNT(*) FROM notification_outbox WHERE source_ip='192.0.2.10' AND status IN ('queued','retry','sending');"));

        fixture.Clock.Advance(TimeSpan.FromMinutes(30));
        await fixture.Service.ProcessOnceAsync(CancellationToken.None);
        Assert.Equal(6, fixture.Sender.Calls.Count);
        // 额度已恢复，但同来源下一封仍需等待实际投递后的十分钟间隔。
        for (var index = 0; index < 4; index++) await fixture.Service.ProcessOnceAsync(CancellationToken.None);
        Assert.Equal(6, fixture.Sender.Calls.Count);
        fixture.Clock.Advance(TimeSpan.FromMinutes(10).Subtract(TimeSpan.FromSeconds(1)));
        await fixture.Service.ProcessOnceAsync(CancellationToken.None);
        Assert.Equal(6, fixture.Sender.Calls.Count);
        fixture.Clock.Advance(TimeSpan.FromSeconds(1));
        await fixture.Service.ProcessOnceAsync(CancellationToken.None);
        Assert.Equal(7, fixture.Sender.Calls.Count);
        var summaries = (await fixture.Service.ListMessagesAsync(1, 100, "sent", "loginFailure", CancellationToken.None)).Items;
        Assert.Contains(summaries, item => item.SourceIp == "192.0.2.10" && item.EventCount == 3);
    }

    [Fact]
    public async Task ConcurrentServiceInstancesClaimOneMessageOnlyOnce()
    {
        using var fixture = await Fixture.CreateAsync();
        await fixture.AddAsync("one-event", "192.0.2.10");
        fixture.Sender.DelayMilliseconds = 40;
        using var second = fixture.CreateService();

        await Task.WhenAll(fixture.Service.ProcessOnceAsync(CancellationToken.None), second.ProcessOnceAsync(CancellationToken.None));

        Assert.Single(fixture.Sender.Calls);
        var sent = Assert.Single((await fixture.Service.ListMessagesAsync(1, 100, "sent", null, CancellationToken.None)).Items);
        Assert.Equal(1, sent.Attempts);
    }

    [Fact]
    public async Task ExpiredSendingLeaseAtRetryBudgetDoesNotAttemptAFifthDelivery()
    {
        using var fixture = await Fixture.CreateAsync();
        var queued = await fixture.Service.QueueTestAsync("recipient@example.test", "tester", null, CancellationToken.None);
        await fixture.ExecuteAsync("UPDATE notification_outbox SET status='sending',attempts=4,next_attempt_at_utc=NULL,lease_until_utc=$lease WHERE id=$id;",
            ("$id", queued.MessageIds[0]), ("$lease", Utc(fixture.Clock.GetUtcNow().AddSeconds(-1))));

        await fixture.Service.ProcessOnceAsync(CancellationToken.None);

        Assert.Empty(fixture.Sender.Calls);
        var detail = await fixture.Service.GetMessageAsync(queued.MessageIds[0], CancellationToken.None);
        Assert.Equal(4, detail.Message.Attempts);
        Assert.Equal("failed", detail.Message.Status);
        Assert.Equal("SMTP_DELIVERY_UNCERTAIN", detail.Message.LastErrorCode);
    }

    [Fact]
    public async Task RecentlySentMailIsRetainedEvenWhenItWasQueuedTwoDaysAgo()
    {
        using var fixture = await Fixture.CreateAsync(retentionDays: 1, queueLifetimeHours: 168);
        var queued = await fixture.Service.QueueTestAsync("recipient@example.test", "tester", null, CancellationToken.None);
        await fixture.ExecuteAsync("UPDATE notification_outbox SET created_at_utc=$created,expires_at_utc=$expires WHERE id=$id;",
            ("$id", queued.MessageIds[0]), ("$created", Utc(fixture.Clock.GetUtcNow().AddDays(-2))),
            ("$expires", Utc(fixture.Clock.GetUtcNow().AddDays(5))));

        await fixture.Service.ProcessOnceAsync(CancellationToken.None);
        await fixture.Service.ProcessOnceAsync(CancellationToken.None);

        Assert.Single(fixture.Sender.Calls);
        var sent = Assert.Single((await fixture.Service.ListMessagesAsync(1, 100, "sent", null, CancellationToken.None)).Items);
        Assert.Equal(queued.MessageIds[0], sent.Id);
        Assert.Equal(fixture.Clock.GetUtcNow(), sent.SentAtUtc);
        var detail = await fixture.Service.GetMessageAsync(sent.Id, CancellationToken.None);
        Assert.NotEmpty(detail.HtmlBody);
        Assert.Equal("sent", detail.Message.Status);
    }

    private static string Utc(DateTimeOffset value) => value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

    private sealed class Fixture : IDisposable
    {
        private readonly SqliteAdminStore store;
        private readonly SqliteConnectionFactory connections;
        private readonly SequentialIds ids = new();
        private readonly NotificationCredentialProtector protector;
        private readonly NotificationTemplateRenderer renderer = new();
        public NotificationService Service { get; }
        public NotificationSettings Settings { get; private set; } = new();
        public TestClock Clock { get; } = new();
        public FakeSender Sender { get; } = new();

        private Fixture(SqliteAdminStore store, SqliteConnectionFactory connections)
        {
            this.store = store;
            this.connections = connections;
            protector = new(store);
            Service = CreateService();
        }

        public static async Task<Fixture> CreateAsync(int maxPerMinute = 100, int maxPerHour = 1000,
            int retentionDays = 30, int queueLifetimeHours = 24)
        {
            var directory = Path.Combine(Path.GetTempPath(), "ipban-notification-queue-regression-tests", Guid.NewGuid().ToString("N"));
            var environment = new TestEnvironment(directory);
            var agentOptions = Microsoft.Extensions.Options.Options.Create(new AgentOptions { DataDirectory = directory, DatabaseFileName = "test.sqlite3" });
            await new SqliteDatabaseInitializer(agentOptions, environment).InitializeAsync();
            var store = new SqliteAdminStore(Microsoft.Extensions.Options.Options.Create(new ManagementDataOptions { DataDirectory = directory, DatabaseFileName = "test.sqlite3" }), environment);
            var fixture = new Fixture(store, new SqliteConnectionFactory(agentOptions, environment));
            fixture.Settings = await fixture.Service.SaveSettingsAsync(new(new NotificationSettings
            {
                Enabled = true, Host = "smtp.example.test", FromAddress = "sender@example.test", Recipients = ["recipient@example.test"],
                MaxPerMinute = maxPerMinute, MaxPerHour = maxPerHour, RetentionDays = retentionDays, QueueLifetimeHours = queueLifetimeHours,
                Rules = [new("loginSuccess", true, 600), new("loginFailure", true, 600), new("ban", true, 600), new("unban", true, 600)]
            }, "synthetic-credential"), "tester", null, CancellationToken.None);
            return fixture;
        }

        public NotificationService CreateService() => new(store, protector, renderer, Sender, ids, Clock);

        public Task AddAsync(string sourceId, string ip, string type = "loginFailure")
        {
            var now = Clock.GetUtcNow();
            var group = type == "loginFailure" ? $"{type}|{ip}|Ssh" : $"{type}|{ip}";
            var snapshot = new NotificationEventSnapshot(type, sourceId, "synthetic-host", ip, "Ssh", "tester", now, type == "ban" ? "Applied" : "Failure");
            return ExecuteAsync("INSERT INTO notification_events(event_key,event_type,group_key,payload_json,config_revision,occurred_at_utc,created_at_utc,priority) VALUES($key,$type,$group,$json,$revision,$now,$now,$priority);",
                ("$key", sourceId), ("$type", type), ("$group", group), ("$json", JsonSerializer.Serialize(snapshot, NotificationJsonContext.Default.NotificationEventSnapshot)),
                ("$revision", Settings.Revision), ("$now", Utc(now)), ("$priority", type == "ban" ? 1 : 0));
        }

        public async Task ExecuteAsync(string sql, params (string Name, object Value)[] args)
        {
            await using var connection = await connections.OpenConnectionAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = sql;
            foreach (var (name, value) in args) command.Parameters.AddWithValue(name, value);
            await command.ExecuteNonQueryAsync();
        }

        public async Task<long> CountAsync(string sql)
        {
            await using var connection = await connections.OpenConnectionAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = sql;
            return Convert.ToInt64(await command.ExecuteScalarAsync(), CultureInfo.InvariantCulture);
        }

        public void Dispose() => Service.Dispose();
    }

    private sealed class FakeSender : INotificationEmailSender
    {
        public List<NotificationEmailEnvelope> Calls { get; } = [];
        public int DelayMilliseconds { get; set; }
        public async Task<NotificationSendResult> SendAsync(NotificationSettings settings, string credential, NotificationEmailEnvelope mail, CancellationToken cancellationToken)
        {
            lock (Calls) Calls.Add(mail);
            if (DelayMilliseconds > 0) await Task.Delay(DelayMilliseconds, cancellationToken);
            return new(true, false);
        }
    }

    private sealed class SequentialIds : IIdService
    {
        private long value = 9007199254740993;
        public long NewId => Interlocked.Increment(ref value);
    }

    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => now;
        public void Advance(TimeSpan duration) => now += duration;
    }

    private sealed class TestEnvironment(string directory) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Testing";
        public string ApplicationName { get; set; } = "IpBan.Api.Tests";
        public string ContentRootPath { get; set; } = directory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
