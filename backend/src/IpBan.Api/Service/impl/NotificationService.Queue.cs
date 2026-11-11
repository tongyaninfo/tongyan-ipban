using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using IpBan.Shared.Logging.Syslog;
using IpBan.Shared.Models;
using Microsoft.Data.Sqlite;

namespace IpBan.Api.Service.impl;

public sealed partial class NotificationService
{
    private const int OutboxCapacity = 1000;

    public async Task<NotificationTestResult> QueueTestAsync(string recipient, string actor, string? remoteIp, CancellationToken ct)
    {
        if (!IsMailbox(recipient)) throw new NotificationRequestException(400, "INVALID_NOTIFICATION_RECIPIENT", "请输入有效的测试收件邮箱。");
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await using var db = await store.OpenNotificationConnectionAsync(ct).ConfigureAwait(false);
            await using var tx = db.BeginTransaction();
            var (settings, credential) = await ReadConfigurationAsync(db, tx, ct).ConfigureAwait(false);
            if (credential is null || settings.Host.Length == 0 || !IsMailbox(settings.FromAddress))
                throw new NotificationRequestException(400, "NOTIFICATION_NOT_CONFIGURED", "请先保存完整的邮件服务配置和授权码。");
            var now = clock.GetUtcNow();
            if (await CountAsync(db, tx, "SELECT COUNT(*) FROM notification_outbox WHERE event_type='test' AND created_at_utc>$since;", ct, ("$since", Utc(now.AddMinutes(-1)))).ConfigureAwait(false) > 0)
                throw new NotificationRequestException(429, "NOTIFICATION_TEST_RATE_LIMITED", "每分钟最多发送一封测试邮件，请稍后重试。");
            if (await PendingCountAsync(db, tx, ct).ConfigureAwait(false) >= OutboxCapacity)
                throw new NotificationRequestException(429, "NOTIFICATION_QUEUE_FULL", "邮件队列已满，请稍后重试。");
            var snapshot = new NotificationEventSnapshot("test", "test", Environment.MachineName, null, null, actor, now, "Test");
            var id = await InsertMessageAsync(db, tx, settings, recipient.Trim(), "test", [snapshot], 2, now, ct).ConfigureAwait(false);
            await SqliteAdminStore.AppendNotificationAuditAsync(db, tx, "notifications.test", id, actor, remoteIp, ct).ConfigureAwait(false);
            await tx.CommitAsync(ct).ConfigureAwait(false);
            store.PublishAudit("notifications.test", id, actor, remoteIp);
            return new([id]);
        }
        finally { gate.Release(); }
    }

    /// <summary>每轮短事务生成/领取任务，提交后才访问 SMTP；租约恢复仅重试邮件，不重做任何防火墙动作。</summary>
    public async Task ProcessOnceAsync(CancellationToken ct)
    {
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await using var db = await store.OpenNotificationConnectionAsync(ct).ConfigureAwait(false);
            NotificationSettings settings;
            string? credential;
            NotificationMessageDetail? mail;
            var queued = new List<string>();
            var now = clock.GetUtcNow();
            await using (var tx = db.BeginTransaction())
            {
                (settings, credential) = await ReadConfigurationAsync(db, tx, ct).ConfigureAwait(false);
                await MaintainQueueAsync(db, tx, settings, now, ct).ConfigureAwait(false);
                if (settings.Enabled && credential is not null) await AggregateAsync(db, tx, settings, now, queued, ct).ConfigureAwait(false);
                mail = await ClaimAsync(db, tx, settings, now, ct).ConfigureAwait(false);
                await tx.CommitAsync(ct).ConfigureAwait(false);
            }
            if (syslog is not null)
                foreach (var id in queued)
                    syslog.Publish("ipban-mail", "mail.queued", SyslogSeverity.Informational, "通知邮件已排队。",
                        result: "queued", sourceId: id);
            if (mail is null) return;
            NotificationSendResult result;
            try
            {
                if (credential is null) result = new(false, false, "SMTP_CREDENTIAL_MISSING", "邮件授权码未配置。");
                else result = await sender.SendAsync(settings, protector.Unprotect(credential),
                    new(mail.MessageId, mail.Message.Recipient, mail.Message.Subject, mail.HtmlBody, mail.TextBody), ct).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is CryptographicException or IOException or UnauthorizedAccessException)
            { result = new(false, false, "SMTP_CREDENTIAL_UNAVAILABLE", "邮件凭据无法读取，请检查密钥文件或重新配置。"); }
            // SMTP 已接收与数据库标记之间无法原子提交；稳定 Message-Id 便于识别极少数崩溃重投。
            var completed = clock.GetUtcNow();
            var retry = !result.Success && result.Retryable && mail.Message.Attempts <= settings.RetryCount;
            var delay = mail.Message.Attempts switch { 1 => 60, 2 => 300, _ => 900 };
            await using var completedTx = db.BeginTransaction();
            await ExecuteAsync(db, completedTx, "UPDATE notification_outbox SET status=$status,sent_at_utc=$sent,next_attempt_at_utc=$next,last_error_code=$code,last_error_message=$message,lease_until_utc=NULL WHERE id=$id AND status='sending';", ct,
                ("$status", result.Success ? "sent" : retry ? "retry" : "failed"), ("$sent", result.Success ? Utc(completed) : null),
                ("$next", retry ? Utc(completed.AddSeconds(delay)) : null), ("$code", result.ErrorCode), ("$message", result.ErrorMessage), ("$id", mail.Message.Id)).ConfigureAwait(false);
            if (result.Success && mail.Message.EventType != "test")
            {
                var group = await ScalarAsync(db, completedTx, "SELECT group_key FROM notification_outbox WHERE id=$id;", ct, ("$id", mail.Message.Id)).ConfigureAwait(false) as string;
                await ExecuteAsync(db, completedTx, "INSERT INTO notification_rate_state(state_key,last_sent_at_utc,updated_at_utc) VALUES($key,$now,$now) ON CONFLICT(state_key) DO UPDATE SET last_sent_at_utc=$now,updated_at_utc=$now;", ct,
                    ("$key", $"delivery:{group}:{mail.Message.Recipient}"), ("$now", Utc(completed))).ConfigureAwait(false);
            }
            await completedTx.CommitAsync(ct).ConfigureAwait(false);
            if (syslog is not null)
            {
                var evt = syslog.CreateEvent("ipban-mail", "mail.delivery", result.Success ? SyslogSeverity.Informational
                    : retry ? SyslogSeverity.Warning : SyslogSeverity.Error,
                    result.Success ? "邮件已提交给 SMTP 服务。" : retry ? "邮件暂未发送，已安排重试。" : "邮件发送失败。",
                    result: result.Success ? "sent" : result.ErrorCode ?? "failed", sourceId: mail.Message.Id);
                syslog.Publish(evt with { EventUid = Guid.NewGuid().ToString("N") });
            }
        }
        finally { gate.Release(); }
    }

    private static Task<long> PendingCountAsync(SqliteConnection db, SqliteTransaction tx, CancellationToken ct) =>
        CountAsync(db, tx, "SELECT COUNT(*) FROM notification_outbox WHERE status IN ('queued','retry','sending');", ct);

    private async Task AggregateAsync(SqliteConnection db, SqliteTransaction tx, NotificationSettings settings, DateTimeOffset now,
        List<string> queued, CancellationToken ct)
    {
        var groups = new List<(string Key, string Type, int Priority)>();
        // 先过滤冷却组和仍有投递任务的组再分页，避免前 50 个热 IP 饿死新的来源提醒。
        await using (var cmd = Command(db, tx, """
            WITH candidates AS (
              SELECT group_key,event_type,MAX(priority) priority,MIN(created_at_utc) created
              FROM notification_events WHERE status='pending' AND config_revision=$revision GROUP BY group_key,event_type
            )
            SELECT c.group_key,c.event_type,c.priority FROM candidates c
            LEFT JOIN notification_rate_state r ON r.state_key=$prefix||c.group_key
            WHERE (r.last_sent_at_utc IS NULL OR r.last_sent_at_utc<=CASE c.event_type
                WHEN 'loginSuccess' THEN $success WHEN 'loginFailure' THEN $failure WHEN 'ban' THEN $ban ELSE $unban END)
              AND NOT EXISTS(SELECT 1 FROM notification_outbox o WHERE o.group_key=c.group_key AND o.config_revision=$revision AND o.status IN ('queued','retry','sending'))
            ORDER BY c.priority DESC,c.created LIMIT 50;
            """, ("$revision", settings.Revision), ("$prefix", $"group:{settings.Revision}:"),
            ("$success", Utc(now.AddSeconds(-settings.Rules.Single(rule => rule.EventType == "loginSuccess").IntervalSeconds))),
            ("$failure", Utc(now.AddSeconds(-settings.Rules.Single(rule => rule.EventType == "loginFailure").IntervalSeconds))),
            ("$ban", Utc(now.AddSeconds(-settings.Rules.Single(rule => rule.EventType == "ban").IntervalSeconds))),
            ("$unban", Utc(now.AddSeconds(-settings.Rules.Single(rule => rule.EventType == "unban").IntervalSeconds)))))
        await using (var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false))
            while (await reader.ReadAsync(ct).ConfigureAwait(false)) groups.Add((reader.GetString(0), reader.GetString(1), reader.GetInt32(2)));
        var pending = await PendingCountAsync(db, tx, ct).ConfigureAwait(false);
        foreach (var group in groups)
        {
            var rule = settings.Rules.FirstOrDefault(rule => rule.EventType == group.Type);
            if (rule is not { Enabled: true }) continue;
            // 为封禁/解封预留队列空间；大量不同 IP 的失败事件不能占满全部投递槽位。
            if (pending + settings.Recipients.Length > (group.Priority > 0 ? OutboxCapacity : OutboxCapacity * 4 / 5)) continue;
            var rateKey = $"group:{settings.Revision}:{group.Key}";
            var last = await ScalarAsync(db, tx, "SELECT last_sent_at_utc FROM notification_rate_state WHERE state_key=$key;", ct, ("$key", rateKey)).ConfigureAwait(false) as string;
            if (last is not null && Parse(last).AddSeconds(rule.IntervalSeconds) > now) continue;
            var events = new List<(string Key, NotificationEventSnapshot Snapshot)>();
            await using (var cmd = Command(db, tx, "SELECT event_key,payload_json FROM notification_events WHERE status='pending' AND group_key=$group AND config_revision=$revision ORDER BY occurred_at_utc,event_key LIMIT 100;", ("$group", group.Key), ("$revision", settings.Revision)))
            await using (var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false))
                while (await reader.ReadAsync(ct).ConfigureAwait(false))
                    events.Add((reader.GetString(0), JsonSerializer.Deserialize(reader.GetString(1), NotificationJsonContext.Default.NotificationEventSnapshot)
                        ?? throw new InvalidDataException("通知事件快照无效。")));
            if (events.Count == 0) continue;
            // 统计本封全部新增事件，正文及历史详情只保留前 100 条样本。
            var totalCount = (int)await CountAsync(db, tx, "SELECT COUNT(*) FROM notification_events WHERE status='pending' AND group_key=$group AND config_revision=$revision;", ct,
                ("$group", group.Key), ("$revision", settings.Revision)).ConfigureAwait(false);
            var lastOccurred = await ScalarAsync(db, tx, "SELECT MAX(occurred_at_utc) FROM notification_events WHERE status='pending' AND group_key=$group AND config_revision=$revision;", ct,
                ("$group", group.Key), ("$revision", settings.Revision)).ConfigureAwait(false) as string;
            var lastOccurredAtUtc = lastOccurred is null ? now : Parse(lastOccurred);
            foreach (var recipient in settings.Recipients)
            {
                DateTimeOffset? initialNotifiedAtUtc = null;
                if (totalCount > 1 && last is not null && group.Type is ("loginSuccess" or "loginFailure"))
                {
                    // 组的频控时间就是上批生成时间。只计入该收件人已由 SMTP 接收的单条通知。
                    var initial = await ScalarAsync(db, tx, """
                        SELECT CASE WHEN json_valid(payload_json) THEN json_extract(payload_json,'$[0].occurredAtUtc') END
                        FROM notification_outbox WHERE created_at_utc=$last AND group_key=$group AND config_revision=$revision
                          AND recipient=$recipient AND status='sent' AND event_count=1;
                        """, ct, ("$last", last), ("$group", group.Key), ("$revision", settings.Revision),
                        ("$recipient", recipient)).ConfigureAwait(false) as string;
                    if (DateTimeOffset.TryParse(initial, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var initialTime)
                        && initialTime <= events[0].Snapshot.OccurredAtUtc && lastOccurredAtUtc <= initialTime.AddSeconds(rule.IntervalSeconds))
                        initialNotifiedAtUtc = initialTime;
                }
                var id = await InsertMessageAsync(db, tx, settings, recipient, group.Key, events.Select(item => item.Snapshot).ToArray(), group.Priority, now, ct, totalCount,
                    lastOccurredAtUtc, initialNotifiedAtUtc).ConfigureAwait(false);
                queued.Add(id);
            }
            await ExecuteAsync(db, tx, "UPDATE notification_events SET status='processed' WHERE status='pending' AND group_key=$group AND config_revision=$revision;", ct,
                ("$group", group.Key), ("$revision", settings.Revision)).ConfigureAwait(false);
            await ExecuteAsync(db, tx, "INSERT INTO notification_rate_state(state_key,last_sent_at_utc,updated_at_utc) VALUES($key,$now,$now) ON CONFLICT(state_key) DO UPDATE SET last_sent_at_utc=$now,updated_at_utc=$now;", ct,
                ("$key", rateKey), ("$now", Utc(now))).ConfigureAwait(false);
            pending += settings.Recipients.Length;
        }
    }

    private async Task<string> InsertMessageAsync(SqliteConnection db, SqliteTransaction tx, NotificationSettings settings, string recipient,
        string group, NotificationEventSnapshot[] events, int priority, DateTimeOffset now, CancellationToken ct,
        int? totalCount = null, DateTimeOffset? lastOccurredAtUtc = null, DateTimeOffset? initialNotifiedAtUtc = null)
    {
        var id = ids.NewId.ToString(CultureInfo.InvariantCulture);
        var email = (totalCount ?? events.Length) > 1
            ? renderer.RenderSummary(events, totalCount, lastOccurredAtUtc, initialNotifiedAtUtc) : renderer.Render(events[0]);
        await ExecuteAsync(db, tx, """
            INSERT INTO notification_outbox(id,event_type,group_key,config_revision,recipient,subject,html_body,text_body,template_version,message_id,payload_json,source_ip,event_count,status,priority,attempts,created_at_utc,expires_at_utc,next_attempt_at_utc)
            VALUES($id,$type,$group,$revision,$recipient,$subject,$html,$text,$version,$messageId,$payload,$ip,$count,'queued',$priority,0,$now,$expires,$now);
            """, ct, ("$id", id), ("$type", events[0].EventType), ("$group", group), ("$revision", settings.Revision),
            ("$recipient", recipient), ("$subject", email.Subject), ("$html", email.HtmlBody), ("$text", email.TextBody), ("$version", email.TemplateVersion),
            ("$messageId", $"ipban-{id}@notifications.local"), ("$payload", JsonSerializer.Serialize(events, NotificationJsonContext.Default.NotificationEventSnapshotArray)),
            ("$ip", events[0].SourceIp), ("$count", totalCount ?? events.Length), ("$priority", priority), ("$now", Utc(now)), ("$expires", Utc(now.AddHours(settings.QueueLifetimeHours)))).ConfigureAwait(false);
        return id;
    }

    private static async Task<NotificationMessageDetail?> ClaimAsync(SqliteConnection db, SqliteTransaction tx, NotificationSettings settings, DateTimeOffset now, CancellationToken ct)
    {
        // 旧进程租约到期后恢复；全局额度在领取时原子扣减，重试与测试同样计数。
        await ExecuteAsync(db, tx, """
            UPDATE notification_outbox SET status='failed',next_attempt_at_utc=NULL,lease_until_utc=NULL,
              last_error_code='SMTP_DELIVERY_UNCERTAIN',last_error_message='上次投递结果无法确认，已达到重试次数或有效期限制，请核实收件结果。'
            WHERE status='sending' AND lease_until_utc<=$now AND (attempts>=$maxAttempts OR expires_at_utc<=$now);
            UPDATE notification_outbox SET status='retry',next_attempt_at_utc=$now,lease_until_utc=NULL,
              last_error_code='SMTP_DELIVERY_UNCERTAIN',last_error_message='上次投递结果无法确认，将在剩余重试次数内重新投递。'
            WHERE status='sending' AND lease_until_utc<=$now;
            """, ct, ("$now", Utc(now)), ("$maxAttempts", settings.RetryCount + 1)).ConfigureAwait(false);
        var id = await ScalarAsync(db, tx, "SELECT id FROM notification_outbox WHERE status IN ('queued','retry') AND config_revision=$revision AND next_attempt_at_utc<=$now AND expires_at_utc>$now AND ($enabled=1 OR event_type='test') ORDER BY priority DESC,created_at_utc,id LIMIT 1;", ct,
            ("$revision", settings.Revision), ("$now", Utc(now)), ("$enabled", settings.Enabled ? 1 : 0)).ConfigureAwait(false);
        if (id is null) return null;
        var current = await ReadDetailAsync(db, tx, Convert.ToString(id, CultureInfo.InvariantCulture)!, ct).ConfigureAwait(false);
        var currentRule = settings.Rules.FirstOrDefault(rule => rule.EventType == current!.Message.EventType);
        if (current!.Message.Attempts == 0 && currentRule is not null)
        {
            var group = await ScalarAsync(db, tx, "SELECT group_key FROM notification_outbox WHERE id=$id;", ct, ("$id", id)).ConfigureAwait(false) as string;
            var lastDelivery = await ScalarAsync(db, tx, "SELECT last_sent_at_utc FROM notification_rate_state WHERE state_key=$key;", ct,
                ("$key", $"delivery:{group}:{current.Message.Recipient}")).ConfigureAwait(false) as string;
            if (lastDelivery is not null && Parse(lastDelivery).AddSeconds(currentRule.IntervalSeconds) > now)
            {
                await ExecuteAsync(db, tx, "UPDATE notification_outbox SET next_attempt_at_utc=$next WHERE id=$id;", ct,
                    ("$id", id), ("$next", Utc(Parse(lastDelivery).AddSeconds(currentRule.IntervalSeconds)))).ConfigureAwait(false);
                return null;
            }
        }
        var priority = await CountAsync(db, tx, "SELECT priority FROM notification_outbox WHERE id=$id;", ct, ("$id", id)).ConfigureAwait(false);
        var minute = await GetWindowAsync(db, tx, "smtp:minute", now, TimeSpan.FromMinutes(1), ct).ConfigureAwait(false);
        var hour = await GetWindowAsync(db, tx, "smtp:hour", now, TimeSpan.FromHours(1), ct).ConfigureAwait(false);
        var lowMinute = await GetWindowAsync(db, tx, "smtp:low:minute", now, TimeSpan.FromMinutes(1), ct).ConfigureAwait(false);
        var lowHour = await GetWindowAsync(db, tx, "smtp:low:hour", now, TimeSpan.FromHours(1), ct).ConfigureAwait(false);
        var next = now;
        if (minute.Count >= settings.MaxPerMinute) next = minute.End;
        if (hour.Count >= settings.MaxPerHour && hour.End > next) next = hour.End;
        if (priority == 0)
        {
            if (lowMinute.Count >= Math.Max(1, settings.MaxPerMinute * 4 / 5) && lowMinute.End > next) next = lowMinute.End;
            if (lowHour.Count >= Math.Max(1, settings.MaxPerHour * 4 / 5) && lowHour.End > next) next = lowHour.End;
        }
        if (next > now)
        {
            await ExecuteAsync(db, tx, "UPDATE notification_outbox SET next_attempt_at_utc=$next WHERE id=$id;", ct, ("$next", Utc(next)), ("$id", id)).ConfigureAwait(false);
            return null;
        }
        await ExecuteAsync(db, tx, "UPDATE notification_rate_state SET count=count+1,updated_at_utc=$now WHERE state_key IN ('smtp:minute','smtp:hour') OR ($low=1 AND state_key IN ('smtp:low:minute','smtp:low:hour'));", ct, ("$now", Utc(now)), ("$low", priority == 0 ? 1 : 0)).ConfigureAwait(false);
        await ExecuteAsync(db, tx, "UPDATE notification_outbox SET status='sending',attempts=attempts+1,lease_until_utc=$lease WHERE id=$id;", ct, ("$lease", Utc(now.AddMinutes(2))), ("$id", id)).ConfigureAwait(false);
        return await ReadDetailAsync(db, tx, Convert.ToString(id, CultureInfo.InvariantCulture)!, ct).ConfigureAwait(false);
    }

    private static async Task<(long Count, DateTimeOffset End)> GetWindowAsync(SqliteConnection db, SqliteTransaction tx, string key, DateTimeOffset now, TimeSpan duration, CancellationToken ct)
    {
        await ExecuteAsync(db, tx, "INSERT INTO notification_rate_state(state_key,window_start_utc,count,updated_at_utc) VALUES($key,$now,0,$now) ON CONFLICT(state_key) DO UPDATE SET count=CASE WHEN window_start_utc<=$since THEN 0 ELSE count END,window_start_utc=CASE WHEN window_start_utc<=$since THEN $now ELSE window_start_utc END,updated_at_utc=$now;", ct,
            ("$key", key), ("$now", Utc(now)), ("$since", Utc(now.Subtract(duration)))).ConfigureAwait(false);
        await using var cmd = Command(db, tx, "SELECT count,window_start_utc FROM notification_rate_state WHERE state_key=$key;", ("$key", key));
        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        await reader.ReadAsync(ct).ConfigureAwait(false);
        return (reader.GetInt64(0), Parse(reader.GetString(1)).Add(duration));
    }

    private static async Task MaintainQueueAsync(SqliteConnection db, SqliteTransaction tx, NotificationSettings settings, DateTimeOffset now, CancellationToken ct)
    {
        await ExecuteAsync(db, tx, """
            UPDATE notification_events SET status='expired' WHERE status='pending' AND created_at_utc<$eventExpiry;
            UPDATE notification_outbox SET status='expired',next_attempt_at_utc=NULL WHERE status IN ('queued','retry') AND expires_at_utc<=$now;
            DELETE FROM notification_events WHERE event_key IN (SELECT event_key FROM notification_events WHERE status<>'pending' AND created_at_utc<$retention LIMIT 1000);
            DELETE FROM notification_outbox WHERE id IN (SELECT id FROM notification_outbox WHERE status IN ('sent','failed','expired','cancelled') AND COALESCE(sent_at_utc,created_at_utc)<$retention LIMIT 1000);
            DELETE FROM notification_rate_state WHERE (state_key LIKE 'group:%' OR state_key LIKE 'delivery:%') AND updated_at_utc<$rateExpiry;
            """, ct, ("$now", Utc(now)), ("$eventExpiry", Utc(now.AddHours(-settings.QueueLifetimeHours))),
            ("$retention", Utc(now.AddDays(-settings.RetentionDays))), ("$rateExpiry", Utc(now.AddDays(-2)))).ConfigureAwait(false);
    }
}
