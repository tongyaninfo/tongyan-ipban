using System.Text.Json;
using IpBan.Shared.Models;
using Microsoft.Data.Sqlite;

namespace IpBan.Api.Service.impl;

public sealed partial class NotificationService
{
    private const string SummaryColumns = "id,event_type,status,recipient,subject,source_ip,event_count,attempts,created_at_utc,sent_at_utc,next_attempt_at_utc,last_error_code,last_error_message";

    public async Task<NotificationMessagePage> ListMessagesAsync(int page, int pageSize, string? status, string? eventType, CancellationToken ct)
    {
        if (page is < 1 or > 100000 || pageSize is < 1 or > 100 || !string.IsNullOrEmpty(status) && status is not ("queued" or "sending" or "retry" or "sent" or "failed" or "expired" or "cancelled")
            || !string.IsNullOrEmpty(eventType) && !EventTypes.Contains(eventType, StringComparer.Ordinal) && eventType != "test")
            throw new NotificationRequestException(400, "INVALID_NOTIFICATION_FILTER", "邮件列表筛选或分页参数无效。");
        await using var db = await store.OpenNotificationConnectionAsync(ct).ConfigureAwait(false);
        const string filter = " WHERE ($status='' OR status=$status) AND ($type='' OR event_type=$type)";
        var args = new (string, object?)[] { ("$status", status ?? ""), ("$type", eventType ?? "") };
        var total = await CountAsync(db, null, "SELECT COUNT(*) FROM notification_outbox" + filter, ct, args).ConfigureAwait(false);
        var rows = new List<NotificationMessageSummary>();
        await using (var cmd = Command(db, null, "SELECT " + SummaryColumns + " FROM notification_outbox" + filter + " ORDER BY created_at_utc DESC,id DESC LIMIT $limit OFFSET $offset;",
            [.. args, ("$limit", pageSize), ("$offset", (page - 1) * pageSize)]))
        await using (var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false))
            while (await reader.ReadAsync(ct).ConfigureAwait(false)) rows.Add(ReadSummary(reader));
        var pending = await CountAsync(db, null, "SELECT COUNT(*) FROM notification_events WHERE status='pending';", ct).ConfigureAwait(false);
        var suppressed = await CountAsync(db, null, "SELECT COALESCE(SUM(suppressed_count),0) FROM notification_rate_state WHERE state_key LIKE 'candidate:overflow:%';", ct).ConfigureAwait(false);
        return new(rows.ToArray(), total, page, pageSize, pending, suppressed);
    }

    public async Task<NotificationMessageDetail> GetMessageAsync(string id, CancellationToken ct)
    {
        if (!long.TryParse(id, out var parsed) || parsed <= 0) throw new NotificationRequestException(400, "INVALID_NOTIFICATION_ID", "邮件记录编号无效。");
        await using var db = await store.OpenNotificationConnectionAsync(ct).ConfigureAwait(false);
        return await ReadDetailAsync(db, null, id, ct).ConfigureAwait(false)
            ?? throw new NotificationRequestException(404, "NOTIFICATION_NOT_FOUND", "邮件记录不存在或已超过留存期限。");
    }

    public NotificationRenderedEmail Preview(string eventType)
    {
        if (!EventTypes.Contains(eventType, StringComparer.Ordinal) && eventType is not ("test" or "summary"))
            throw new NotificationRequestException(400, "INVALID_NOTIFICATION_TYPE", "通知类型无效。");
        var status = eventType switch { "loginSuccess" => "Success", "loginFailure" => "Failure", "ban" => "Applied", "unban" => "Removed", _ => "Test" };
        var snapshot = new NotificationEventSnapshot(eventType == "summary" ? "loginFailure" : eventType, "preview", "示例主机", "192.0.2.25", "Ssh", "demo-user",
            clock.GetUtcNow(), status, "preview", "此内容为模板预览，未发送邮件。", eventType == "ban" ? 1800 : null, "示例防火墙",
            LocalIp: "198.51.100.20");
        return eventType == "summary" ? renderer.RenderSummary([snapshot with { Status = "Failure" }, snapshot with { Status = "Failure", SourceId = "preview-2", OccurredAtUtc = snapshot.OccurredAtUtc.AddSeconds(30) }]) : renderer.Render(snapshot);
    }

    private static async Task<NotificationMessageDetail?> ReadDetailAsync(SqliteConnection db, SqliteTransaction? tx, string id, CancellationToken ct)
    {
        await using var cmd = Command(db, tx, "SELECT " + SummaryColumns + ",html_body,text_body,template_version,message_id,payload_json FROM notification_outbox WHERE id=$id;", ("$id", id));
        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) return null;
        return new(ReadSummary(reader), reader.GetString(13), reader.GetString(14), reader.GetString(15), reader.GetString(16),
            JsonSerializer.Deserialize(reader.GetString(17), NotificationJsonContext.Default.NotificationEventSnapshotArray) ?? []);
    }

    private static NotificationMessageSummary ReadSummary(SqliteDataReader reader) => new(
        reader.GetInt64(0).ToString(System.Globalization.CultureInfo.InvariantCulture), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetString(4),
        reader.IsDBNull(5) ? null : reader.GetString(5), reader.GetInt32(6), reader.GetInt32(7), Parse(reader.GetString(8)),
        reader.IsDBNull(9) ? null : Parse(reader.GetString(9)), reader.IsDBNull(10) ? null : Parse(reader.GetString(10)),
        reader.IsDBNull(11) ? null : reader.GetString(11), reader.IsDBNull(12) ? null : reader.GetString(12));
}
