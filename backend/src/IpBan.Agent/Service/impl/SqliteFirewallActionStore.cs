using System.Globalization;
using IpBan.Shared.Models;
using IpBan.Shared.Logging.Syslog;
using IpBan.Agent.Models;
using Microsoft.Data.Sqlite;

namespace IpBan.Agent.Service.impl;

/// <summary>
/// 持久化每次防火墙决定和执行结果，便于管理台区分 Applied、Failed、Disabled 和 Removed。
/// </summary>
public sealed class SqliteFirewallActionStore(ISqliteConnectionFactory connectionFactory, SyslogRuntime? syslog = null) : IFirewallActionStore
{
    public Task<long> AppendAsync(string action, FirewallActionResult result, CancellationToken cancellationToken = default) =>
        AppendAsync(action, result, null, cancellationToken);

    public async Task<long> AppendAsync(string action, FirewallActionResult result, FirewallNotificationContext? notificationContext,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO firewall_actions(source_ip, action, status, provider, error_code, error_message, created_at_utc, completed_at_utc) VALUES ($source, $action, $status, $provider, $code, $message, $created, $completed) RETURNING id;";
        command.Parameters.AddWithValue("$source", result.SourceAddress);
        command.Parameters.AddWithValue("$action", action);
        command.Parameters.AddWithValue("$status", result.ActionStatus.ToString());
        command.Parameters.AddWithValue("$provider", result.Provider);
        command.Parameters.AddWithValue("$code", (object?)result.ErrorCode ?? DBNull.Value);
        command.Parameters.AddWithValue("$message", (object?)result.ErrorMessage ?? DBNull.Value);
        command.Parameters.AddWithValue("$created", result.CompletedAtUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$completed", result.ActionStatus is FirewallActionStatus.Applied or FirewallActionStatus.Removed ? result.CompletedAtUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture) : DBNull.Value);
        var id = Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture);
        var eventType = action switch
        {
            "ban" or "auto-ban" => "ban",
            "unban" or "auto-unban" or "manual-unban" => "unban",
            _ => null
        };
        if (eventType is not null)
        {
            // 仅复制真实动作结果；Disabled/Failed 不能渲染成“已封禁”或“已解封”。
            var snapshot = new NotificationEventSnapshot(eventType, id.ToString(CultureInfo.InvariantCulture),
                Environment.MachineName, result.SourceAddress, notificationContext?.Protocol, null, result.CompletedAtUtc,
                result.ActionStatus.ToString(), action, notificationContext?.Reason ?? result.ErrorCode,
                notificationContext?.DurationSeconds, result.Provider,
                notificationContext?.OriginalActionId?.ToString(CultureInfo.InvariantCulture));
            await SqliteNotificationEventWriter.AppendAsync(connection, transaction, $"firewall:{id}", snapshot, cancellationToken).ConfigureAwait(false);
        }
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        if (eventType == "ban")
        {
            var message = result.ActionStatus switch
            {
                FirewallActionStatus.Applied => "防火墙封禁已生效。",
                FirewallActionStatus.Disabled => "防火墙已停用，未执行封禁。",
                FirewallActionStatus.Pending => "封禁等待执行。",
                _ => "防火墙封禁执行失败。"
            };
            syslog?.Publish("ipban-ban", action == "auto-ban" ? "ban.automatic.result" : "ban.manual.result",
                SyslogSeverity.Emergency, message, result: result.ActionStatus.ToString(),
                sourceId: id.ToString(CultureInfo.InvariantCulture), remoteIp: result.SourceAddress,
                protocol: notificationContext?.Protocol, traceId: notificationContext?.TraceId, occurredAtUtc: result.CompletedAtUtc);
        }
        else if (eventType == "unban")
        {
            var removed = result.ActionStatus == FirewallActionStatus.Removed;
            syslog?.Publish("ipban-unban", "unban.result", removed ? SyslogSeverity.Notice : SyslogSeverity.Error,
                removed ? "封禁已解除。" : "解除封禁失败。", priority: true, result: result.ActionStatus.ToString(),
                sourceId: id.ToString(CultureInfo.InvariantCulture), remoteIp: result.SourceAddress,
                traceId: notificationContext?.TraceId, occurredAtUtc: result.CompletedAtUtc);
        }
        return id;
    }
}
