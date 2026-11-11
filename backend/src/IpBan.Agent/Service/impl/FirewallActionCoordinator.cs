using System.Globalization;
using IpBan.Agent.Models;
using IpBan.Shared.Models;
using IpBan.Shared.Logging.Syslog;

namespace IpBan.Agent.Service.impl;

/// <summary>
/// 同一 Agent 内串行化防火墙变更和动作持久化。解除必须匹配当前封禁代次，
/// 历史 timer、重复按钮和陈旧页面不能解除随后新建的封禁。
/// </summary>
public sealed class FirewallActionCoordinator(
    ISqliteConnectionFactory connectionFactory,
    IFirewallActionStore actionStore,
    IEnumerable<IFirewallProvider> providers,
    SyslogRuntime? syslog = null) : IDisposable
{
    private readonly SemaphoreSlim gate = new(1, 1);

    public async Task<RecordedFirewallAction> BanAsync(IFirewallProvider provider, string source,
        string action, CancellationToken cancellationToken, DateTimeOffset? evidenceThroughUtc = null,
        FirewallNotificationContext? notificationContext = null, DateTimeOffset? thresholdEvidenceFromUtc = null)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (action == "auto-ban"
                && await ShouldSkipActiveBanAsync(provider, source, thresholdEvidenceFromUtc, cancellationToken).ConfigureAwait(false))
            {
                return new RecordedFirewallAction(0, new FirewallActionResult(provider.Name, source,
                    FirewallActionStatus.Failed, FirewallStatus.Enabled, "POLICY_SOURCE_ALREADY_BANNED",
                    "该来源已有生效的封禁，不重复下发。", DateTimeOffset.UtcNow));
            }
            if (evidenceThroughUtc is { } evidenceTime && await WasEvidenceHandledAfterAsync(source, evidenceTime, cancellationToken).ConfigureAwait(false))
            {
                return new RecordedFirewallAction(0, new FirewallActionResult(provider.Name, source,
                    FirewallActionStatus.Failed, FirewallStatus.Enabled, "POLICY_SNAPSHOT_EXPIRED",
                    "该批失败事件已经处置，不重复封禁。", DateTimeOffset.UtcNow));
            }
            syslog?.Publish("ipban-ban", action == "auto-ban" ? "ban.automatic.decision" : "ban.manual.decision",
                SyslogSeverity.Emergency, action == "auto-ban" ? "登录失败达到策略阈值，决定执行自动封禁。" : "已接收人工封禁决定。",
                result: "Decision", remoteIp: source, protocol: notificationContext?.Protocol, traceId: notificationContext?.TraceId);
            FirewallActionResult result;
            try { result = await provider.BanAsync(source, cancellationToken).ConfigureAwait(false); }
            catch (Exception error) when (error is not OperationCanceledException)
            {
                syslog?.Publish("ipban-ban", "ban.execution.exception", SyslogSeverity.Emergency,
                    "调用防火墙执行封禁时发生异常。", result: "Unknown", remoteIp: source, traceId: notificationContext?.TraceId);
                throw;
            }
            var id = await actionStore.AppendAsync(action, result, notificationContext, cancellationToken).ConfigureAwait(false);
            return new RecordedFirewallAction(id, result);
        }
        finally { gate.Release(); }
    }

    public async Task<ApiResult<FirewallActionResult>> UnbanAsync(long actionId, string source,
        CancellationToken cancellationToken, string? traceId = null)
    {
        if (actionId <= 0 || !FirewallAddressValidator.TryNormalize(source, out var normalized))
        {
            return ApiResult<FirewallActionResult>.Fail("INVALID_BAN_ACTION", "封禁记录或来源地址无效。");
        }
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // 从服务器持久化记录决定来源和 provider，客户端只能选择要解除的封禁。
            var original = await ReadActionAsync(actionId, cancellationToken).ConfigureAwait(false);
            if (original is null)
                return ApiResult<FirewallActionResult>.Fail("BAN_NOT_FOUND", "封禁记录不存在。");
            if (!string.Equals(normalized, original.Value.Source, StringComparison.Ordinal)
                || !await IsCurrentCoreAsync(normalized, actionId, cancellationToken).ConfigureAwait(false))
                return ApiResult<FirewallActionResult>.Fail("BAN_NOT_CURRENT", "该记录已解除或已被新的封禁替代，请刷新。");
            var provider = providers.FirstOrDefault(item => item.Name == original.Value.Provider);
            if (provider is null)
                return ApiResult<FirewallActionResult>.Fail("FIREWALL_PROVIDER_UNAVAILABLE", "原封禁的防火墙执行器不可用。");

            var result = await provider.UnbanAsync(original.Value.Source, cancellationToken).ConfigureAwait(false);
            await actionStore.AppendAsync("manual-unban", result,
                new FirewallNotificationContext("人工解除封禁", OriginalActionId: actionId, TraceId: traceId), cancellationToken).ConfigureAwait(false);
            return result.ActionStatus == FirewallActionStatus.Removed
                ? ApiResult<FirewallActionResult>.Ok(result, "封禁已手动解除。")
                : new ApiResult<FirewallActionResult>(false, "FIREWALL_UNBAN_FAILED", "防火墙未能解除封禁。", result);
        }
        finally { gate.Release(); }
    }

    public async Task<FirewallActionResult?> ExpireAsync(IFirewallProvider provider, string source,
        long actionId, string action, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!await IsCurrentCoreAsync(source, actionId, cancellationToken).ConfigureAwait(false)) return null;
            var result = await provider.UnbanAsync(source, cancellationToken).ConfigureAwait(false);
            await actionStore.AppendAsync(action, result,
                new FirewallNotificationContext("封禁时长到期，执行解除", OriginalActionId: actionId), cancellationToken).ConfigureAwait(false);
            return result;
        }
        finally { gate.Release(); }
    }

    public async Task<bool> WhileCurrentAsync(string source, long actionId, Func<Task> action,
        CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!await IsCurrentCoreAsync(source, actionId, cancellationToken).ConfigureAwait(false)) return false;
            await action().ConfigureAwait(false);
            return true;
        }
        finally { gate.Release(); }
    }

    private async Task<bool> IsCurrentCoreAsync(string source, long actionId, CancellationToken cancellationToken)
    {
        await using var connection = await connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT id, status FROM firewall_actions WHERE source_ip=$source AND ((action IN ('ban','auto-ban') AND status='Applied') OR (action IN ('unban','auto-unban','manual-unban') AND status='Removed')) ORDER BY id DESC LIMIT 1;";
        command.Parameters.AddWithValue("$source", source);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
            && reader.GetInt64(0) == actionId && reader.GetString(1) == "Applied";
    }

    private async Task<bool> ShouldSkipActiveBanAsync(IFirewallProvider provider, string source,
        DateTimeOffset? thresholdEvidenceFromUtc, CancellationToken cancellationToken)
    {
        var active = await ReadActiveBanCoreAsync(source, cancellationToken).ConfigureAwait(false);
        if (active is null)
        {
            return false;
        }

        // 只有新证据重新达标且已确认旧 nftables 规则缺失，才允许本次新处置。
        // 其余情况仍按原代次去重，避免重复规则或重放历史事件。
        if (provider is NftablesFirewallProvider nftables && active.Value.Provider == provider.Name
            && thresholdEvidenceFromUtc > active.Value.CreatedAtUtc)
        {
            return await nftables.HasSourceRuleAsync(source, cancellationToken).ConfigureAwait(false) != false;
        }

        return true;
    }

    private async Task<(string Provider, DateTimeOffset? CreatedAtUtc)?> ReadActiveBanCoreAsync(
        string source, CancellationToken cancellationToken)
    {
        await using var connection = await connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT status, provider, created_at_utc FROM firewall_actions WHERE source_ip=$source AND ((action IN ('ban','auto-ban') AND status='Applied') OR (action IN ('unban','auto-unban','manual-unban') AND status='Removed')) ORDER BY id DESC LIMIT 1;";
        command.Parameters.AddWithValue("$source", source);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) || reader.GetString(0) != "Applied")
        {
            return null;
        }

        return (reader.GetString(1), DateTimeOffset.TryParse(reader.GetString(2), CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind, out var createdAt) ? createdAt : null);
    }

    private async Task<bool> WasEvidenceHandledAfterAsync(string source, DateTimeOffset evidenceTime, CancellationToken cancellationToken)
    {
        await using var connection = await connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        // 与判定查询保持同一证据水位，避免判定快照在自动到期之后才取得锁而重新封禁。
        command.CommandText = "SELECT EXISTS(SELECT 1 FROM firewall_actions WHERE source_ip=$source AND ((action='manual-unban' AND status='Removed') OR (action='auto-ban' AND status='Applied')) AND created_at_utc >= $evidence);";
        command.Parameters.AddWithValue("$source", source);
        command.Parameters.AddWithValue("$evidence", evidenceTime.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture));
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture) != 0;
    }

    private async Task<(string Source, string Provider)?> ReadActionAsync(long id, CancellationToken cancellationToken)
    {
        await using var connection = await connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT source_ip, provider FROM firewall_actions WHERE id=$id AND action IN ('ban','auto-ban') AND status='Applied';";
        command.Parameters.AddWithValue("$id", id);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ? (reader.GetString(0), reader.GetString(1)) : null;
    }

    public void Dispose() => gate.Dispose();
}
