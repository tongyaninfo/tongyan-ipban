using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using IpBan.Agent.Models;
using IpBan.Agent.Options;
using IpBan.Agent.Service.impl;
using IpBan.Api.Options;
using IpBan.Api.Service;
using IpBan.Api.Service.impl;
using IpBan.Shared.Models;
using IpBan.Shared.Service;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;

namespace IpBan.Api.Tests;

/// <summary>隔离数据库、可推进时钟和假 SMTP 验证完整流程；不连接邮件服务、不操作防火墙、不删除测试文件。</summary>
public sealed class NotificationWorkflowTests
{
    [Fact]
    public async Task SettingsProtectCredentialPreserveBlankAndRejectStaleRevision()
    {
        using var fixture = await Fixture.CreateAsync();
        var first = await fixture.ConfigureAsync();
        var encrypted = Assert.IsType<string>(await fixture.ScalarAsync("SELECT setting_value FROM system_settings WHERE setting_key='notifications.credential';"));
        Assert.NotEqual(Fixture.SyntheticCredential, encrypted);
        Assert.True(first.HasCredential);
        Assert.DoesNotContain(Fixture.SyntheticCredential,
            JsonSerializer.Serialize(first, NotificationJsonContext.Default.NotificationSettings), StringComparison.Ordinal);
        var second = await fixture.Service.SaveSettingsAsync(new(first with { FromName = "修改后的名称" }, ""), "tester", null, CancellationToken.None);
        Assert.Equal(encrypted, await fixture.ScalarAsync("SELECT setting_value FROM system_settings WHERE setting_key='notifications.credential';"));
        Assert.NotEqual(first.Revision, second.Revision);
        Assert.Equal(first.EnabledSinceUtc, second.EnabledSinceUtc);
        var conflict = await Assert.ThrowsAsync<NotificationRequestException>(() =>
            fixture.Service.SaveSettingsAsync(new(first), "tester", null, CancellationToken.None));
        Assert.Equal(409, conflict.Status);
        Assert.Equal(second.Revision, (await fixture.Service.GetSettingsAsync(CancellationToken.None)).Revision);
        var generic = Assert.Single(await fixture.Store.ListSettingsAsync(), setting => setting.Key == NotificationService.CredentialKey);
        Assert.Null(generic.Value);
        Assert.True(generic.IsSecret);
    }

    [Fact]
    public async Task AuditFailureRollsBackSettingsAndQueueCancellation()
    {
        using var fixture = await Fixture.CreateAsync();
        var settings = await fixture.ConfigureAsync();
        var queued = await fixture.Service.QueueTestAsync("test@example.com", "tester", null, CancellationToken.None);
        await fixture.ExecuteAsync("CREATE TRIGGER deny_notification_audit BEFORE INSERT ON audit_records BEGIN SELECT RAISE(ABORT,'synthetic audit unavailable'); END;");

        await Assert.ThrowsAsync<SqliteException>(() => fixture.Service.SaveSettingsAsync(
            new(settings with { Enabled = false, FromName = "should not persist" }), "tester", null, CancellationToken.None));

        var actual = await fixture.Service.GetSettingsAsync(CancellationToken.None);
        Assert.Equal(settings.Revision, actual.Revision);
        Assert.True(actual.Enabled);
        Assert.Equal(settings.FromName, actual.FromName);
        Assert.Equal("queued", (await fixture.Service.GetMessageAsync(queued.MessageIds[0], CancellationToken.None)).Message.Status);
    }

    [Fact]
    public async Task FourAgentEventTypesFlowThroughPersistentQueueToRecordedMessages()
    {
        using var fixture = await Fixture.CreateAsync();
        await fixture.ConfigureAsync();
        fixture.Clock.Advance(TimeSpan.FromSeconds(1));
        var now = fixture.Clock.GetUtcNow();
        var logins = new SqliteLoginEventStore(fixture.AgentFactory);
        await logins.AppendAsync(Login(1, now, success: true));
        await logins.AppendAsync(Login(2, now, success: false));
        var actions = new SqliteFirewallActionStore(fixture.AgentFactory);
        var ban = await actions.AppendAsync("auto-ban", new("synthetic", "192.0.2.10", FirewallActionStatus.Applied,
            FirewallStatus.Enabled, null, null, now), new FirewallNotificationContext("合成策略触发", 300, Protocol: "Ssh"));
        await actions.AppendAsync("manual-unban", new("synthetic", "192.0.2.10", FirewallActionStatus.Removed,
            FirewallStatus.Enabled, null, null, now), new FirewallNotificationContext("人工解除", OriginalActionId: ban));

        for (var index = 0; index < 4; index++) await fixture.Service.ProcessOnceAsync(CancellationToken.None);

        var page = await fixture.Service.ListMessagesAsync(1, 100, "sent", null, CancellationToken.None);
        Assert.Equal(4, page.Total);
        Assert.Equal(["ban", "loginFailure", "loginSuccess", "unban"], page.Items.Select(item => item.EventType).Order(StringComparer.Ordinal));
        Assert.Equal(4, fixture.Sender.Calls.Count);
        Assert.Equal(0L, await fixture.ScalarAsync("SELECT COUNT(*) FROM notification_events WHERE status='pending';"));
        var unban = await fixture.Service.GetMessageAsync(Assert.Single(page.Items, item => item.EventType == "unban").Id, CancellationToken.None);
        Assert.Equal(ban.ToString(CultureInfo.InvariantCulture), Assert.Single(unban.Events).OriginalActionId);
        Assert.All(page.Items, item => Assert.Equal(1, item.Attempts));
    }

    [Fact]
    public async Task FirstEventSendsImmediatelyAndLaterEventsBecomeOneTimedSummary()
    {
        using var fixture = await Fixture.CreateAsync();
        await fixture.ConfigureAsync();
        await fixture.AddCandidateAsync("first");
        await fixture.Service.ProcessOnceAsync(CancellationToken.None);
        Assert.Single(fixture.Sender.Calls);
        fixture.Clock.Advance(TimeSpan.FromSeconds(10));
        await fixture.AddCandidateAsync("second");
        await fixture.AddCandidateAsync("third");
        await fixture.Service.ProcessOnceAsync(CancellationToken.None);
        Assert.Single(fixture.Sender.Calls);
        Assert.Equal(2L, await fixture.ScalarAsync("SELECT COUNT(*) FROM notification_events WHERE status='pending';"));

        fixture.Clock.Advance(TimeSpan.FromSeconds(50));
        await fixture.Service.ProcessOnceAsync(CancellationToken.None);

        Assert.Equal(2, fixture.Sender.Calls.Count);
        var page = await fixture.Service.ListMessagesAsync(1, 100, "sent", null, CancellationToken.None);
        var summary = Assert.Single(page.Items, item => item.EventCount == 2);
        var detail = await fixture.Service.GetMessageAsync(summary.Id, CancellationToken.None);
        Assert.Equal(["second", "third"], detail.Events.Select(item => item.SourceId));
        Assert.Contains("汇总", detail.Message.Subject, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("loginFailure", 10, true, true)]
    [InlineData("loginSuccess", 10, true, true)]
    [InlineData("loginFailure", 58, true, false)]
    [InlineData("loginFailure", 61, true, false)]
    [InlineData("loginFailure", 10, false, false)]
    public async Task LoginSummaryCountsPreviouslyNotifiedFirstEventOnlyWithinItsOccurrenceInterval(
        string eventType, int firstFollowupDelaySeconds, bool firstWasSent, bool expectedRoundTotal)
    {
        using var fixture = await Fixture.CreateAsync();
        const string recipient = "recipient@example.com";
        const string otherRecipient = "other@example.com";
        string[] recipients = firstWasSent ? [recipient] : [recipient, otherRecipient];
        await fixture.ConfigureAsync(settings => settings with { Recipients = recipients });
        if (!firstWasSent)
        {
            // 同一组的首条发给另一收件人成功，不能算作当前收件人已收到。
            fixture.Sender.Handler = (mail, _) => mail.Recipient == recipient
                ? new(false, false, "SMTP_PERMANENT", "合成永久失败")
                : new(true, false);
        }
        await fixture.AddCandidateAsync("first", eventType);
        for (var index = 0; index < recipients.Length; index++)
            await fixture.Service.ProcessOnceAsync(CancellationToken.None);
        Assert.Equal(recipients.Length, fixture.Sender.Calls.Count);
        var firstPage = await fixture.Service.ListMessagesAsync(1, 100,
            firstWasSent ? "sent" : "failed", eventType, CancellationToken.None);
        Assert.Equal(1, Assert.Single(firstPage.Items, item => item.Recipient == recipient).EventCount);
        if (!firstWasSent)
        {
            var sent = await fixture.Service.ListMessagesAsync(1, 100, "sent", eventType, CancellationToken.None);
            Assert.Equal(otherRecipient, Assert.Single(sent.Items).Recipient);
        }
        fixture.Sender.Handler = null;

        fixture.Clock.Advance(TimeSpan.FromSeconds(firstFollowupDelaySeconds));
        string[] followups = ["second", "third", "fourth", "fifth"];
        foreach (var sourceId in followups)
        {
            await fixture.AddCandidateAsync(sourceId, eventType);
            fixture.Clock.Advance(TimeSpan.FromSeconds(1));
        }

        // 各场景都在发信冷却结束后汇总，是否纳入首条取决于全部新增事件的发生时间。
        fixture.Clock.Advance(TimeSpan.FromSeconds(60));
        for (var index = 0; index < recipients.Length; index++)
            await fixture.Service.ProcessOnceAsync(CancellationToken.None);

        Assert.Equal(2 * recipients.Length, fixture.Sender.Calls.Count);
        var page = await fixture.Service.ListMessagesAsync(1, 100, "sent", eventType, CancellationToken.None);
        var summary = Assert.Single(page.Items, item => item.Recipient == recipient && item.EventCount == 4);
        var detail = await fixture.Service.GetMessageAsync(summary.Id, CancellationToken.None);
        Assert.Equal(followups, detail.Events.Select(item => item.SourceId));

        var htmlText = Regex.Replace(WebUtility.HtmlDecode(Regex.Replace(detail.HtmlBody, "<[^>]+>", " ")), @"\s+", " ");
        foreach (var body in new[] { htmlText, detail.TextBody })
        {
            if (expectedRoundTotal)
            {
                Assert.Contains("本轮累计 5 次", body, StringComparison.Ordinal);
                Assert.Contains("含已单独通知的首条 1 次", body, StringComparison.Ordinal);
                Assert.Contains("本封新增 4 次", body, StringComparison.Ordinal);
            }
            else
            {
                Assert.DoesNotContain("本轮累计 5 次", body, StringComparison.Ordinal);
                Assert.DoesNotContain("含已单独通知的首条", body, StringComparison.Ordinal);
            }
        }
    }

    [Fact]
    public async Task RecipientRetriesNeverResendSuccessfulRecipients()
    {
        using var fixture = await Fixture.CreateAsync();
        await fixture.ConfigureAsync(settings => settings with { Recipients = ["first@example.com", "retry@example.com"] });
        fixture.Sender.Handler = (mail, attempt) => mail.Recipient == "retry@example.com" && attempt == 1
            ? new(false, true, "SMTP_TEMPORARY", "合成暂时失败") : new(true, false);
        await fixture.AddCandidateAsync("one-event");
        await fixture.Service.ProcessOnceAsync(CancellationToken.None);
        await fixture.Service.ProcessOnceAsync(CancellationToken.None);
        var retry = Assert.Single((await fixture.Service.ListMessagesAsync(1, 100, "retry", null, CancellationToken.None)).Items);
        Assert.Equal(1, retry.Attempts);
        await fixture.Service.ProcessOnceAsync(CancellationToken.None);
        Assert.Equal(2, fixture.Sender.Calls.Count);

        fixture.Clock.Advance(TimeSpan.FromSeconds(60));
        await fixture.Service.ProcessOnceAsync(CancellationToken.None);

        Assert.Single(fixture.Sender.Calls, item => item.Recipient == "first@example.com");
        var retries = fixture.Sender.Calls.Where(item => item.Recipient == "retry@example.com").ToArray();
        Assert.Equal(2, retries.Length);
        Assert.Equal(retries[0].MessageId, retries[1].MessageId);
        Assert.Equal(2, (await fixture.Service.GetMessageAsync(retry.Id, CancellationToken.None)).Message.Attempts);
        Assert.Equal(2, (await fixture.Service.ListMessagesAsync(1, 100, "sent", null, CancellationToken.None)).Total);
    }

    [Fact]
    public async Task GlobalLimitsSurviveServiceRestartAndReserveSpaceForBanEvents()
    {
        using var fixture = await Fixture.CreateAsync();
        await fixture.ConfigureAsync(settings => settings with { MaxPerMinute = 5, MaxPerHour = 20 });
        for (var index = 0; index < 5; index++)
            await fixture.AddCandidateAsync($"failure-{index}", sourceIp: $"192.0.2.{index + 1}");
        for (var index = 0; index < 5; index++) await fixture.Service.ProcessOnceAsync(CancellationToken.None);
        Assert.Equal(4, fixture.Sender.Calls.Count);
        await fixture.AddCandidateAsync("important-ban", "ban");
        await fixture.Service.ProcessOnceAsync(CancellationToken.None);
        Assert.Equal(5, fixture.Sender.Calls.Count);
        Assert.Contains("封禁", fixture.Sender.Calls[^1].Subject, StringComparison.Ordinal);

        fixture.RestartService();
        await fixture.AddCandidateAsync("important-unban", "unban");
        await fixture.Service.ProcessOnceAsync(CancellationToken.None);
        Assert.Equal(5, fixture.Sender.Calls.Count);
        Assert.Equal(5L, await fixture.ScalarAsync("SELECT count FROM notification_rate_state WHERE state_key='smtp:minute';"));
        fixture.Clock.Advance(TimeSpan.FromSeconds(60));
        await fixture.Service.ProcessOnceAsync(CancellationToken.None);
        Assert.Equal(6, fixture.Sender.Calls.Count);
        Assert.Contains("解封", fixture.Sender.Calls[^1].Subject, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DisablingCancelsPendingWorkAndPreservesSentSnapshots()
    {
        using var fixture = await Fixture.CreateAsync();
        var settings = await fixture.ConfigureAsync();
        await fixture.AddCandidateAsync("sent-event", sourceIp: "192.0.2.1");
        await fixture.AddCandidateAsync("queued-event", sourceIp: "192.0.2.2");
        await fixture.Service.ProcessOnceAsync(CancellationToken.None);
        var sent = Assert.Single((await fixture.Service.ListMessagesAsync(1, 100, "sent", null, CancellationToken.None)).Items);
        var detailBefore = await fixture.Service.GetMessageAsync(sent.Id, CancellationToken.None);
        await fixture.AddCandidateAsync("pending-event", sourceIp: "192.0.2.3");

        await fixture.Service.SaveSettingsAsync(new(settings with { Enabled = false }), "tester", null, CancellationToken.None);
        await fixture.Service.ProcessOnceAsync(CancellationToken.None);

        Assert.Single(fixture.Sender.Calls);
        Assert.Equal(1, (await fixture.Service.ListMessagesAsync(1, 100, "cancelled", null, CancellationToken.None)).Total);
        Assert.Equal(1L, await fixture.ScalarAsync("SELECT COUNT(*) FROM notification_events WHERE status='cancelled';"));
        var detailAfter = await fixture.Service.GetMessageAsync(sent.Id, CancellationToken.None);
        Assert.Equal("sent", detailAfter.Message.Status);
        Assert.Equal(detailBefore.HtmlBody, detailAfter.HtmlBody);
        Assert.Equal(detailBefore.TemplateVersion, detailAfter.TemplateVersion);
        Assert.Equal(detailBefore.Events, detailAfter.Events);
    }

    [Fact]
    public async Task DisabledSystemCanSendTestWithOneMinuteCooldown()
    {
        using var fixture = await Fixture.CreateAsync();
        await fixture.ConfigureAsync(settings => settings with { Enabled = false });
        var test = await fixture.Service.QueueTestAsync("test@example.com", "tester", null, CancellationToken.None);
        var limited = await Assert.ThrowsAsync<NotificationRequestException>(() =>
            fixture.Service.QueueTestAsync("another@example.com", "tester", null, CancellationToken.None));
        Assert.Equal(429, limited.Status);
        await fixture.Service.ProcessOnceAsync(CancellationToken.None);
        Assert.Equal("test@example.com", Assert.Single(fixture.Sender.Calls).Recipient);
        Assert.Equal("sent", (await fixture.Service.GetMessageAsync(test.MessageIds[0], CancellationToken.None)).Message.Status);

        fixture.Clock.Advance(TimeSpan.FromMinutes(1));
        await fixture.Service.QueueTestAsync("another@example.com", "tester", null, CancellationToken.None);
        Assert.Equal(2L, await fixture.ScalarAsync("SELECT COUNT(*) FROM audit_records WHERE action='notifications.test';"));
    }

    [Fact]
    public async Task ExpiredQueueAndExpiredCandidateNeverSend()
    {
        using var fixture = await Fixture.CreateAsync();
        await fixture.ConfigureAsync(settings => settings with { QueueLifetimeHours = 1 });
        var test = await fixture.Service.QueueTestAsync("test@example.com", "tester", null, CancellationToken.None);
        await fixture.AddCandidateAsync("expired-event");
        fixture.Clock.Advance(TimeSpan.FromHours(1).Add(TimeSpan.FromSeconds(1)));
        await fixture.Service.ProcessOnceAsync(CancellationToken.None);

        Assert.Empty(fixture.Sender.Calls);
        Assert.Equal("expired", (await fixture.Service.GetMessageAsync(test.MessageIds[0], CancellationToken.None)).Message.Status);
        Assert.Equal("expired", await fixture.ScalarAsync("SELECT status FROM notification_events WHERE event_key='synthetic:expired-event';"));
    }

    [Fact]
    public async Task ExpiredLeaseRecoversWithSameMessageIdAndIncrementedAttempt()
    {
        using var fixture = await Fixture.CreateAsync();
        await fixture.ConfigureAsync();
        var queued = await fixture.Service.QueueTestAsync("test@example.com", "tester", null, CancellationToken.None);
        var detail = await fixture.Service.GetMessageAsync(queued.MessageIds[0], CancellationToken.None);
        await fixture.ExecuteAsync("UPDATE notification_outbox SET status='sending',attempts=1,next_attempt_at_utc=NULL,lease_until_utc=$lease;",
            ("$lease", Utc(fixture.Clock.GetUtcNow().AddSeconds(-1))));

        await fixture.Service.ProcessOnceAsync(CancellationToken.None);

        Assert.Equal(detail.MessageId, Assert.Single(fixture.Sender.Calls).MessageId);
        var recovered = await fixture.Service.GetMessageAsync(detail.Message.Id, CancellationToken.None);
        Assert.Equal("sent", recovered.Message.Status);
        Assert.Equal(2, recovered.Message.Attempts);
    }

    [Fact]
    public async Task SentFilterPaginationAndDetailsUseStoredSnapshots()
    {
        using var fixture = await Fixture.CreateAsync();
        await fixture.ConfigureAsync();
        for (var index = 0; index < 4; index++)
            await fixture.AddCandidateAsync($"event-{index}", sourceIp: $"192.0.2.{index + 1}");
        for (var index = 0; index < 3; index++) await fixture.Service.ProcessOnceAsync(CancellationToken.None);

        var first = await fixture.Service.ListMessagesAsync(1, 2, "sent", "loginFailure", CancellationToken.None);
        var second = await fixture.Service.ListMessagesAsync(2, 2, "sent", "loginFailure", CancellationToken.None);
        Assert.Equal(3, first.Total);
        Assert.Equal(2, first.Items.Length);
        Assert.Single(second.Items);
        Assert.Empty(first.Items.Select(item => item.Id).Intersect(second.Items.Select(item => item.Id)));
        var selected = await fixture.Service.GetMessageAsync(first.Items[0].Id, CancellationToken.None);
        Assert.Contains("synthetic-host", selected.TextBody, StringComparison.Ordinal);
        Assert.Equal(first.Items[0].SourceIp, Assert.Single(selected.Events).SourceIp);
        Assert.StartsWith("通研IPBan-", selected.Message.Subject, StringComparison.Ordinal);
        Assert.NotEmpty(selected.HtmlBody);
        Assert.NotEmpty(selected.TemplateVersion);
        var missing = await Assert.ThrowsAsync<NotificationRequestException>(() => fixture.Service.GetMessageAsync("1", CancellationToken.None));
        Assert.Equal(404, missing.Status);
        var malformed = await Assert.ThrowsAsync<NotificationRequestException>(() => fixture.Service.GetMessageAsync("bad-id", CancellationToken.None));
        Assert.Equal(400, malformed.Status);
    }

    private static string Utc(DateTimeOffset value) => value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
    private static LoginEventContract Login(long id, DateTimeOffset occurred, bool success) => new(
        id, occurred, ProtocolKind.Ssh, success, "synthetic-user", "192.0.2.10", 42000, "192.0.2.20", 22,
        42, "sshd", null, null, EventCompletenessLevel.IpEnforceable,
        FieldAvailability.Available, FieldAvailability.Available, FieldAvailability.Available,
        FieldAvailability.Available, "synthetic-notification-api", $"event-{id}", "synthetic");

    private sealed class Fixture : IDisposable
    {
        internal const string SyntheticCredential = "synthetic-only-mail-authorization";
        private readonly SequentialIds ids = new();
        private readonly NotificationCredentialProtector protector;
        private readonly NotificationTemplateRenderer renderer = new();
        private Fixture(SqliteAdminStore store, SqliteConnectionFactory agentFactory)
        {
            Store = store;
            AgentFactory = agentFactory;
            protector = new(store);
            Service = CreateService();
        }

        public SqliteAdminStore Store { get; }
        public SqliteConnectionFactory AgentFactory { get; }
        public NotificationService Service { get; private set; }
        public TestClock Clock { get; } = new();
        public FakeSender Sender { get; } = new();

        public static async Task<Fixture> CreateAsync()
        {
            var directory = Path.Combine(Path.GetTempPath(), "ipban-notification-workflow-tests", Guid.NewGuid().ToString("N"));
            var environment = new TestEnvironment(directory);
            var agentOptions = Microsoft.Extensions.Options.Options.Create(new AgentOptions { DataDirectory = directory, DatabaseFileName = "test.sqlite3" });
            await new SqliteDatabaseInitializer(agentOptions, environment).InitializeAsync();
            var store = new SqliteAdminStore(Microsoft.Extensions.Options.Options.Create(new ManagementDataOptions
            {
                DataDirectory = directory, DatabaseFileName = "test.sqlite3"
            }), environment);
            return new(store, new SqliteConnectionFactory(agentOptions, environment));
        }

        public async Task<NotificationSettings> ConfigureAsync(Func<NotificationSettings, NotificationSettings>? customize = null)
        {
            var current = await Service.GetSettingsAsync(CancellationToken.None);
            var settings = current with
            {
                Enabled = true, Host = "smtp.example.com", Port = 465, Security = "ssl", FromAddress = "sender@example.com",
                Recipients = ["recipient@example.com"], MaxPerMinute = 100, MaxPerHour = 1000,
                Rules = [new("loginSuccess", true, 60), new("loginFailure", true, 60), new("ban", true, 60), new("unban", true, 60)]
            };
            return await Service.SaveSettingsAsync(new(customize?.Invoke(settings) ?? settings, SyntheticCredential), "tester", "192.0.2.30", CancellationToken.None);
        }

        public async Task AddCandidateAsync(string sourceId, string type = "loginFailure", string sourceIp = "192.0.2.10")
        {
            var settings = await Service.GetSettingsAsync(CancellationToken.None);
            var now = Clock.GetUtcNow();
            var status = type switch { "loginSuccess" => "Success", "loginFailure" => "Failure", "ban" => "Applied", _ => "Removed" };
            var snapshot = new NotificationEventSnapshot(type, sourceId, "synthetic-host", sourceIp, "Ssh", "synthetic-user", now, status);
            var group = type switch
            {
                "loginSuccess" => $"{type}|{sourceIp}|Ssh|synthetic-user",
                "loginFailure" => $"{type}|{sourceIp}|Ssh",
                _ => $"{type}|{sourceIp}"
            };
            await ExecuteAsync("INSERT INTO notification_events(event_key,event_type,group_key,payload_json,config_revision,occurred_at_utc,created_at_utc,priority) VALUES($key,$type,$group,$json,$revision,$now,$now,$priority);",
                ("$key", $"synthetic:{sourceId}"), ("$type", type), ("$group", group),
                ("$json", JsonSerializer.Serialize(snapshot, NotificationJsonContext.Default.NotificationEventSnapshot)),
                ("$revision", settings.Revision), ("$now", Utc(now)), ("$priority", type is "ban" or "unban" ? 1 : 0));
        }

        public async Task<object?> ScalarAsync(string sql)
        {
            await using var db = await AgentFactory.OpenConnectionAsync();
            await using var cmd = db.CreateCommand();
            cmd.CommandText = sql;
            return await cmd.ExecuteScalarAsync();
        }

        public async Task ExecuteAsync(string sql, params (string Name, object? Value)[] values)
        {
            await using var db = await AgentFactory.OpenConnectionAsync();
            await using var cmd = db.CreateCommand();
            cmd.CommandText = sql;
            foreach (var (name, value) in values) cmd.Parameters.AddWithValue(name, value ?? DBNull.Value);
            await cmd.ExecuteNonQueryAsync();
        }

        private NotificationService CreateService() => new(Store, protector, renderer, Sender, ids, Clock);
        public void RestartService() { Service.Dispose(); Service = CreateService(); }
        public void Dispose() => Service.Dispose();
    }

    private sealed class SequentialIds : IIdService
    {
        private long value = 9007199254740993;
        public long NewId => Interlocked.Increment(ref value);
    }

    private sealed class FakeSender : INotificationEmailSender
    {
        public List<NotificationEmailEnvelope> Calls { get; } = [];
        public Func<NotificationEmailEnvelope, int, NotificationSendResult>? Handler { get; set; }
        public Task<NotificationSendResult> SendAsync(NotificationSettings settings, string credential,
            NotificationEmailEnvelope mail, CancellationToken cancellationToken)
        {
            Assert.Equal(Fixture.SyntheticCredential, credential);
            Calls.Add(mail);
            var attempt = Calls.Count(item => item.MessageId == mail.MessageId);
            return Task.FromResult(Handler?.Invoke(mail, attempt) ?? new(true, false));
        }
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
