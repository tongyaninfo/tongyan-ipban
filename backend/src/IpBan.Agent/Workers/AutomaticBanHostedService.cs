using System.Collections.Concurrent;
using System.Globalization;
using IpBan.Agent.Service;
using IpBan.Agent.Service.impl;
using IpBan.Agent.Models;
using IpBan.Engine.Models;
using IpBan.Engine.Services;
using IpBan.Shared.Models;
using IpBan.Shared.Logging.Syslog;
using IpBan.Shared.Service;
using Microsoft.Data.Sqlite;

namespace IpBan.Agent.Workers;

/// <summary>
/// 根据登录失败事件和已启用策略执行自动封禁。
/// 之前只有纯判定器和人工封禁入口，没有把策略接到采集事件上，导致启用策略也不会真正封禁。
/// </summary>
public sealed partial class AutomaticBanHostedService(
    ISqliteConnectionFactory connectionFactory,
    IFirewallProviderSelector firewallProviderSelector,
    IFirewallActionStore firewallActionStore,
    FirewallActionCoordinator actionCoordinator,
    IConnectionSnapshotProvider snapshotProvider,
    IConnectionTerminator connectionTerminator,
    ILogger<AutomaticBanHostedService> logger,
    SyslogRuntime? syslog = null) : BackgroundService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(2);
    private readonly ConcurrentDictionary<long, byte> scheduledUnbans = new();

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // 等数据库初始化 HostedService 完成首轮迁移后再读取策略。
        await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken).ConfigureAwait(false);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await EvaluatePoliciesAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception) when (exception is InvalidOperationException or IOException or SqliteException)
            {
                LogEvaluationFailed(exception);
            }

            try
            {
                await Task.Delay(PollInterval, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
        }
    }

    internal async Task EvaluatePoliciesAsync(CancellationToken cancellationToken)
    {
        var policies = await ReadPoliciesAsync(cancellationToken).ConfigureAwait(false);
        if (policies.Count == 0)
        {
            return;
        }

        var maxWindow = policies.Max(policy => policy.WindowSeconds);
        var failures = await ReadFailuresAsync(
            DateTimeOffset.UtcNow.AddSeconds(-maxWindow),
            cancellationToken).ConfigureAwait(false);
        if (failures.Count == 0)
        {
            return;
        }

        foreach (var policy in policies)
        {
            if (!string.Equals(policy.Action, "Ban", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var since = DateTimeOffset.UtcNow.AddSeconds(-policy.WindowSeconds);
            foreach (var sourceGroup in failures
                .Where(failure => failure.OccurredAtUtc >= since)
                .GroupBy(failure => failure.RemoteIp, StringComparer.OrdinalIgnoreCase))
            {
                var matchingFailures = sourceGroup
                    .Where(failure => MatchesPolicyProtocol(policy.Protocol, failure.Protocol))
                    .OrderBy(failure => failure.OccurredAtUtc)
                    .ToArray();
                // 采集器只输出明确的认证结果。随后成功不抹去之前真实输错的密码，
                // 同一 TCP 连接上的不同认证结果也必须分别计入阈值。
                if (matchingFailures.Length < policy.Threshold)
                {
                    continue;
                }

                var sourceIp = sourceGroup.Key;
                if (await HasRecentAutomaticBanAsync(sourceIp, policy.CooldownSeconds, cancellationToken).ConfigureAwait(false))
                {
                    continue;
                }

                var protocol = matchingFailures[^1].Protocol;
                var decision = BanDecisionEvaluator.Evaluate(new DecisionInput(
                    sourceIp,
                    protocol,
                    matchingFailures.Length,
                    IsWhitelisted: false,
                    IsBlacklisted: false,
                    new BanPolicySnapshot(
                        policy.Version,
                        policy.Threshold,
                        TimeSpan.FromSeconds(policy.WindowSeconds),
                        TimeSpan.FromSeconds(Math.Max(0, policy.BanDurationSeconds)),
                        Enabled: true),
                    DateTimeOffset.UtcNow));
                if (decision.Action != DecisionAction.Ban)
                {
                    continue;
                }

                await ApplyAutomaticBanAsync(sourceIp, policy, matchingFailures[^policy.Threshold].OccurredAtUtc,
                    matchingFailures[^1].OccurredAtUtc, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task ApplyAutomaticBanAsync(
        string sourceIp,
        PolicyRow policy,
        DateTimeOffset thresholdEvidenceFromUtc,
        DateTimeOffset evidenceThroughUtc,
        CancellationToken cancellationToken)
    {
        var platform = OperatingSystem.IsWindows() ? "windows" : "linux";
        var notificationContext = new FirewallNotificationContext(
            $"策略「{policy.Name}」版本 {policy.Version}：{policy.WindowSeconds} 秒内登录失败达到 {policy.Threshold} 次",
            policy.BanDurationSeconds, Protocol: policy.Protocol, TraceId: Guid.NewGuid().ToString("N"));
        var selection = await firewallProviderSelector.SelectAsync(platform, cancellationToken).ConfigureAwait(false);
        if (selection.Provider is null)
        {
            syslog?.Publish("ipban-ban", "ban.automatic.decision", SyslogSeverity.Emergency,
                $"登录失败在 {policy.WindowSeconds} 秒内达到 {policy.Threshold} 次，决定执行自动封禁。",
                result: "Decision", remoteIp: sourceIp, protocol: policy.Protocol, traceId: notificationContext.TraceId);
            var status = selection.Observation.Status == FirewallStatus.Disabled
                ? FirewallActionStatus.Disabled
                : FirewallActionStatus.Failed;
            await firewallActionStore.AppendAsync(
                "auto-ban",
                new FirewallActionResult(
                    selection.Observation.Provider,
                    sourceIp,
                    status,
                    selection.Observation.Status,
                    $"FIREWALL_{selection.Observation.Status.ToString().ToUpperInvariant()}",
                    selection.Observation.Detail,
                    DateTimeOffset.UtcNow),
                notificationContext, cancellationToken).ConfigureAwait(false);
            return;
        }

        var recorded = await actionCoordinator.BanAsync(selection.Provider, sourceIp, "auto-ban", cancellationToken,
            evidenceThroughUtc, notificationContext, thresholdEvidenceFromUtc).ConfigureAwait(false);
        var action = recorded.Result;
        if (action.ActionStatus != FirewallActionStatus.Applied)
        {
            return;
        }

        try
        {
            await actionCoordinator.WhileCurrentAsync(sourceIp, recorded.Id, async () =>
            {
                var connections = await snapshotProvider.QueryAsync(cancellationToken).ConfigureAwait(false);
                var matchingConnections = connections
                    .Where(connection => string.Equals(connection.RemoteIp, sourceIp, StringComparison.OrdinalIgnoreCase))
                    .ToArray();
                if (matchingConnections.Length > 0)
                {
                    await connectionTerminator.TerminateAsync(matchingConnections, cancellationToken).ConfigureAwait(false);
                }
            }, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is InvalidOperationException or IOException)
        {
            LogConnectionTerminationFailed(sourceIp, exception);
        }

        // -1 和旧版保存的 0 均表示永久封禁，保留手动解封路径。
        if (policy.BanDurationSeconds > 0 && scheduledUnbans.TryAdd(recorded.Id, 0))
        {
            _ = ScheduleUnbanAsync(selection.Provider, sourceIp, recorded.Id, policy.BanDurationSeconds, cancellationToken);
        }
    }

    private async Task ScheduleUnbanAsync(
        IFirewallProvider provider,
        string sourceIp,
        long actionId,
        int durationSeconds,
        CancellationToken cancellationToken)
    {
        try
        {
            // 有限时长允许 Int32 范围内的秒数；分段等待避免超过 Task.Delay 的单次计时上限。
            var remaining = TimeSpan.FromSeconds(durationSeconds);
            while (remaining > TimeSpan.Zero)
            {
                var slice = remaining > TimeSpan.FromDays(1) ? TimeSpan.FromDays(1) : remaining;
                await Task.Delay(slice, cancellationToken).ConfigureAwait(false);
                remaining -= slice;
            }
            await actionCoordinator.ExpireAsync(provider, sourceIp, actionId, "auto-unban", cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Agent 停止时不自动恢复既有规则。
        }
        catch (Exception exception) when (exception is InvalidOperationException or IOException)
        {
            LogExpiryFailed(sourceIp, exception);
        }
        finally
        {
            scheduledUnbans.TryRemove(actionId, out _);
        }
    }

    private async Task<bool> HasRecentAutomaticBanAsync(
        string sourceIp,
        int cooldownSeconds,
        CancellationToken cancellationToken)
    {
        await using var connection = await connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        // 成功手动解封结束此前的处置周期，不能让旧冷却阻止解封后的新失败达到阈值。
        // 旧事件仍由 ReadFailuresAsync 的处置水位排除；失败解封及其他来源不重置冷却。
        // 用动作代次而非时间精度区分先后，新的自动动作也不会被更早的解封抵消。
        command.CommandText = "SELECT EXISTS(SELECT 1 FROM firewall_actions b WHERE b.source_ip=$source AND b.action='auto-ban' AND b.status IN ('Applied','Pending','Failed','Disabled') AND b.created_at_utc >= $since AND NOT EXISTS (SELECT 1 FROM firewall_actions u WHERE u.source_ip=b.source_ip AND u.action='manual-unban' AND u.status='Removed' AND u.id>b.id));";
        command.Parameters.AddWithValue("$source", sourceIp);
        command.Parameters.AddWithValue("$since", DateTimeOffset.UtcNow.AddSeconds(-Math.Max(1, cooldownSeconds)).ToString("O", CultureInfo.InvariantCulture));
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture) != 0;
    }

    private async Task<IReadOnlyList<PolicyRow>> ReadPoliciesAsync(CancellationToken cancellationToken)
    {
        await using var connection = await connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT id, enabled, threshold, window_seconds, cooldown_seconds, ban_duration_seconds, action, protocol, version, name FROM ban_policies WHERE enabled=1 AND threshold > 0 AND window_seconds > 0 AND ban_duration_seconds >= -1;";
        var result = new List<PolicyRow>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            result.Add(new PolicyRow(
                reader.GetInt64(0),
                reader.GetInt32(2),
                reader.GetInt32(3),
                reader.GetInt32(4),
                reader.GetInt32(5),
                reader.GetString(6),
                reader.IsDBNull(7) ? null : reader.GetString(7),
                reader.GetInt32(8),
                reader.GetString(9)));
        }
        return result;
    }

    private async Task<IReadOnlyList<FailureRow>> ReadFailuresAsync(
        DateTimeOffset sinceUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = await connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        // 成功封禁已处置此前的失败；冷却结束或自动到期不能再次使用同一批证据。
        // 手动解封同样重置该来源。失败/停用的防火墙动作不消耗证据，仍可按冷却期重试。
        command.CommandText = "SELECT remote_ip, remote_port, protocol, occurred_at_utc, evidence_source, local_process_name FROM login_events e WHERE is_success=0 AND remote_ip IS NOT NULL AND occurred_at_utc >= $since AND NOT EXISTS (SELECT 1 FROM firewall_actions a WHERE a.source_ip=e.remote_ip AND ((a.action='manual-unban' AND a.status='Removed') OR (a.action='auto-ban' AND a.status='Applied')) AND a.created_at_utc >= e.occurred_at_utc) ORDER BY occurred_at_utc;";
        command.Parameters.AddWithValue("$since", sinceUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        var result = new List<FailureRow>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            var storedProtocol = LoginEventProtocol.ResolveStored(reader.GetString(2), reader.GetString(4),
                reader.IsDBNull(5) ? null : reader.GetString(5));
            if (Enum.TryParse<ProtocolKind>(storedProtocol, true, out var protocol)
                && DateTimeOffset.TryParse(reader.GetString(3), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var occurredAtUtc))
            {
                result.Add(new FailureRow(
                    reader.GetString(0),
                    reader.IsDBNull(1) ? null : reader.GetInt32(1),
                    protocol,
                    occurredAtUtc));
            }
        }
        return result;
    }

    internal static bool MatchesPolicyProtocol(string? policyProtocol, ProtocolKind eventProtocol) =>
        string.IsNullOrWhiteSpace(policyProtocol)
        || string.Equals(policyProtocol, "ALL", StringComparison.OrdinalIgnoreCase)
        || (string.Equals(policyProtocol, nameof(ProtocolKind.Ssh), StringComparison.OrdinalIgnoreCase)
            && eventProtocol is ProtocolKind.Ssh or ProtocolKind.OpenSsh)
        || string.Equals(policyProtocol, eventProtocol.ToString(), StringComparison.OrdinalIgnoreCase);

    private sealed record PolicyRow(
        long Id,
        int Threshold,
        int WindowSeconds,
        int CooldownSeconds,
        int BanDurationSeconds,
        string Action,
        string? Protocol,
        long Version,
        string Name);

    private sealed record FailureRow(string RemoteIp, int? RemotePort, ProtocolKind Protocol, DateTimeOffset OccurredAtUtc);

    [LoggerMessage(Level = LogLevel.Warning, Message = "自动封禁策略本轮执行失败，下一轮继续。")]
    private partial void LogEvaluationFailed(Exception exception);

    [LoggerMessage(Level = LogLevel.Error, Message = "自动封禁后断开来源 {SourceIp} 的已有连接失败。")]
    private partial void LogConnectionTerminationFailed(string sourceIp, Exception exception);

    [LoggerMessage(Level = LogLevel.Error, Message = "自动封禁到期解封 {SourceIp} 失败。")]
    private partial void LogExpiryFailed(string sourceIp, Exception exception);
}
