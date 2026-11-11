using System.Security.Cryptography;
using System.Text;
using IpBan.Shared.Models;
using IpBan.Api.Service.impl;
using IpBan.Shared.Logging.Syslog;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Data.Sqlite;

namespace IpBan.Api.Service;

/// <summary>
/// 轮询 Agent 的连接和登录事件快照，变化后通知已订阅的管理台页面刷新查询。
/// </summary>
public sealed class ManagementRealtimeWorker(
    IAgentIpcClient agentClient,
    SqliteAdminStore store,
    IHubContext<ManagementHub> hubContext,
    SyslogRuntime syslog) : BackgroundService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan OverviewHeartbeat = TimeSpan.FromSeconds(5);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        string? connectionsFingerprint = null;
        string? eventsFingerprint = null;
        long? lastFirewallActionId = null;
        var lastOverviewNotification = DateTimeOffset.MinValue;
        var consecutiveFailures = 0;

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var connections = await agentClient.ListConnectionsAsync(stoppingToken).ConfigureAwait(false);
                var events = await agentClient.ListLoginEventsAsync(200, stoppingToken).ConfigureAwait(false);
                var healthy = connections.Success && events.Success;
                // 封禁通常晚于登录事件入库，手动解封也不会产生登录事件。
                // 单独观察动作序号，保证已打开的封禁页面能收到状态变化通知。
                var nextFirewallActionId = await store.GetLatestFirewallActionIdAsync(stoppingToken).ConfigureAwait(false);
                var firewallActionsChanged = nextFirewallActionId != lastFirewallActionId;
                lastFirewallActionId = nextFirewallActionId;
                var nextConnectionsFingerprint = connections.Success && connections.Data is not null
                    ? FingerprintConnections(connections.Data)
                    : connectionsFingerprint;
                var nextEventsFingerprint = events.Success && events.Data is not null
                    ? FingerprintEvents(events.Data)
                    : eventsFingerprint;
                var connectionsChanged = connections.Success && connections.Data is not null
                    && !string.Equals(nextConnectionsFingerprint, connectionsFingerprint, StringComparison.Ordinal);
                var eventsChanged = events.Success && events.Data is not null
                    && !string.Equals(nextEventsFingerprint, eventsFingerprint, StringComparison.Ordinal);
                connectionsFingerprint = nextConnectionsFingerprint;
                eventsFingerprint = nextEventsFingerprint;
                var now = DateTimeOffset.UtcNow;

                if (connectionsChanged)
                {
                    await PublishAsync("connections", now, stoppingToken).ConfigureAwait(false);
                }

                if (eventsChanged || firewallActionsChanged)
                {
                    await PublishAsync("security-events", now, stoppingToken).ConfigureAwait(false);
                }

                if (connectionsChanged || eventsChanged || firewallActionsChanged || now - lastOverviewNotification >= OverviewHeartbeat)
                {
                    await PublishAsync("overview", now, stoppingToken).ConfigureAwait(false);
                    lastOverviewNotification = now;
                }
                if (!healthy) RecordFailure();
                else if (consecutiveFailures > 0)
                {
                    consecutiveFailures = 0;
                    syslog.Publish("ipban-http", "realtime.recovered", SyslogSeverity.Notice, "管理台实时数据轮询已恢复。");
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception) when (exception is IOException or InvalidOperationException or SqliteException)
            {
                RecordFailure();
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

        void RecordFailure()
        {
            if (consecutiveFailures >= 3) return;
            consecutiveFailures++;
            if (consecutiveFailures == 1)
                syslog.Publish("ipban-http", "realtime.unavailable", SyslogSeverity.Warning, "管理台实时数据轮询暂不可用。");
            else if (consecutiveFailures == 3)
                syslog.Publish("ipban-http", "realtime.degraded", SyslogSeverity.Error, "管理台实时数据连续三轮未刷新。");
        }
    }

    private async Task PublishAsync(string channel, DateTimeOffset atUtc, CancellationToken cancellationToken)
    {
        await hubContext.Clients
            .Group(ManagementHub.GroupName(channel))
            .SendAsync(ManagementHub.DataChangedEvent, new ManagementRealtimeEvent(channel, atUtc), cancellationToken)
            .ConfigureAwait(false);
    }

    private static string FingerprintConnections(IReadOnlyList<ConnectionSnapshotContract> connections) =>
        Hash(string.Join('\n', connections.OrderBy(item => item.RemoteIp, StringComparer.Ordinal)
            .ThenBy(item => item.RemotePort)
            .ThenBy(item => item.LocalIp, StringComparer.Ordinal)
            .ThenBy(item => item.LocalPort)
            .Select(item => string.Join('|', item.Protocol, item.State, item.RemoteIp, item.RemotePort, item.LocalIp, item.LocalPort, item.ProcessId, item.ProcessName))));

    private static string FingerprintEvents(IReadOnlyList<LoginEventContract> events) =>
        Hash(string.Join('\n', events.OrderByDescending(item => item.OccurredAtUtc)
            .Take(200)
            .Select(item => string.Join('|', item.Id, item.OccurredAtUtc, item.Protocol, item.Success, item.RemoteIp, item.RemotePort, item.Username))));

    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

}
