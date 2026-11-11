using System.Globalization;
using System.Net;
using System.Text.Json;
using IpBan.Shared.Models;
using Microsoft.Data.Sqlite;

namespace IpBan.Agent.Service.impl;

/// <summary>
/// 复用业务写事务保存有界通知候选；这里不访问 SMTP，也不读取或解密邮件凭据。
/// </summary>
internal static class SqliteNotificationEventWriter
{
    private const int MaximumPendingEvents = 10000;

    public static async Task AppendAsync(SqliteConnection connection, SqliteTransaction transaction,
        string eventKey, NotificationEventSnapshot snapshot, CancellationToken cancellationToken)
    {
        await using var settingCommand = connection.CreateCommand();
        settingCommand.Transaction = transaction;
        settingCommand.CommandText = "SELECT setting_value FROM system_settings WHERE setting_key='notifications.settings' AND is_secret=0;";
        var json = await settingCommand.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as string;
        if (string.IsNullOrWhiteSpace(json) || json.Length > 65536) return;

        NotificationSettings? settings;
        try
        {
            settings = JsonSerializer.Deserialize(json, NotificationJsonContext.Default.NotificationSettings);
        }
        catch (JsonException)
        {
            // 无效通知配置不能阻断主机登录采集或已经执行的防火墙动作。
            return;
        }
        var now = DateTimeOffset.UtcNow;
        if (settings is not { Enabled: true, EnabledSinceUtc: { } enabledSince }
            || snapshot.OccurredAtUtc <= enabledSince
            || snapshot.OccurredAtUtc < now.AddHours(-Math.Clamp(settings.QueueLifetimeHours, 1, 24))
            || settings.Rules?.Any(rule => rule is not null && rule.Enabled && rule.EventType == snapshot.EventType) != true)
        {
            return;
        }

        await using var capacityCommand = connection.CreateCommand();
        capacityCommand.Transaction = transaction;
        capacityCommand.CommandText = "SELECT COUNT(*) FROM (SELECT 1 FROM notification_events WHERE status='pending' LIMIT 10000);";
        // 与下游发件队列保持同样的优先级边界，登录风暴不能用尽封禁/解封候选空间。
        var candidateLimit = snapshot.EventType is "loginSuccess" or "loginFailure"
            ? MaximumPendingEvents * 4 / 5 : MaximumPendingEvents;
        if (Convert.ToInt64(await capacityCommand.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture) >= candidateLimit)
        {
            // 固定四种类型的计数键，不让攻击者通过轮换 IP 无限制造限流状态。
            await using var overflow = connection.CreateCommand();
            overflow.Transaction = transaction;
            overflow.CommandText = "INSERT INTO notification_rate_state(state_key,suppressed_count,updated_at_utc) VALUES($key,1,$now) ON CONFLICT(state_key) DO UPDATE SET suppressed_count=suppressed_count+1,updated_at_utc=excluded.updated_at_utc;";
            overflow.Parameters.AddWithValue("$key", $"candidate:overflow:{snapshot.EventType}");
            overflow.Parameters.AddWithValue("$now", now.ToString("O", CultureInfo.InvariantCulture));
            await overflow.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            return;
        }

        snapshot = snapshot with
        {
            OccurredAtUtc = snapshot.OccurredAtUtc.ToUniversalTime(),
            HostName = Limit(snapshot.HostName, 256) ?? "",
            SourceIp = NormalizeAddress(snapshot.SourceIp),
            LocalIp = snapshot.EventType is "loginSuccess" or "loginFailure"
                ? NormalizeLocalAddress(snapshot.LocalIp) ?? PhysicalNetworkAddress.Find()
                : null,
            Protocol = Limit(snapshot.Protocol, 64),
            Username = Limit(snapshot.Username, 256),
            Reason = Limit(snapshot.Reason, 1024),
            Provider = Limit(snapshot.Provider, 128),
            Action = Limit(snapshot.Action, 64)
        };
        var groupKey = snapshot.EventType switch
        {
            "loginSuccess" => $"{snapshot.EventType}|{snapshot.SourceIp}|{snapshot.Protocol}|{snapshot.Username}",
            "loginFailure" => $"{snapshot.EventType}|{snapshot.SourceIp}|{snapshot.Protocol}",
            _ => $"{snapshot.EventType}|{snapshot.SourceIp}"
        };
        await using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = "INSERT INTO notification_events(event_key,event_type,group_key,payload_json,config_revision,occurred_at_utc,created_at_utc,priority) VALUES($key,$type,$group,$payload,$revision,$occurred,$created,$priority) ON CONFLICT(event_key) DO NOTHING;";
        insert.Parameters.AddWithValue("$key", eventKey);
        insert.Parameters.AddWithValue("$type", snapshot.EventType);
        insert.Parameters.AddWithValue("$group", groupKey);
        insert.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(snapshot, NotificationJsonContext.Default.NotificationEventSnapshot));
        insert.Parameters.AddWithValue("$revision", settings.Revision ?? "");
        insert.Parameters.AddWithValue("$occurred", snapshot.OccurredAtUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        insert.Parameters.AddWithValue("$created", now.ToString("O", CultureInfo.InvariantCulture));
        insert.Parameters.AddWithValue("$priority", snapshot.EventType is "ban" or "unban" ? 1 : 0);
        await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static string? NormalizeAddress(string? value)
    {
        if (IPAddress.TryParse(value, out var address))
            return (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString();
        return FirewallAddressValidator.TryNormalize(value, out var normalized) ? normalized : Limit(value, 128);
    }

    private static string? NormalizeLocalAddress(string? value)
    {
        if (!IPAddress.TryParse(value, out var address)) return null;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        return address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.Broadcast)
            ? null
            : address.ToString();
    }

    private static string? Limit(string? value, int length) => value?.Length > length ? value[..length] : value;
}
