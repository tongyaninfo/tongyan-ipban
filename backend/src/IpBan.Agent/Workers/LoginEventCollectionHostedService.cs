using System.Collections.Concurrent;
using IpBan.Agent.Service;
using IpBan.Engine.Services;
using IpBan.Shared.Models;
using IpBan.Shared.Service;
using Microsoft.Data.Sqlite;

namespace IpBan.Agent.Workers;

/// <summary>
/// 周期读取各平台登录证据，归一化后写入 SQLite。采集失败只影响本轮，不阻断 Agent 和防火墙探测。
/// </summary>
public sealed partial class LoginEventCollectionHostedService(
    IEnumerable<ILoginEventCollector> collectors,
    ILoginEventStore eventStore,
    IIdService idService,
    IConnectionSnapshotProvider connectionSnapshotProvider,
    ILogger<LoginEventCollectionHostedService> logger) : BackgroundService
{
    // 登录事件采集使用短轮询，避免用户登录后要等待原来的 30 秒窗口才出现在管理台。
    // 事件采集保持短轮询，确保登录后管理台通常在数秒内可见。
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(2);
    // 日志写入可晚于其发生时间；有限重叠读取由稳定原始证据 ID 防重，不合并真实认证。
    private static readonly TimeSpan EvidenceOverlap = TimeSpan.FromSeconds(30);
    private readonly ConcurrentDictionary<string, byte> seenEvidence = new(StringComparer.Ordinal);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var initialSinceUtc = DateTimeOffset.UtcNow.Subtract(EvidenceOverlap);
        var watermarks = collectors.ToDictionary(collector => collector, _ => initialSinceUtc);
        while (!stoppingToken.IsCancellationRequested)
        {
            var scanStartedAtUtc = DateTimeOffset.UtcNow;

            IReadOnlyList<ConnectionSnapshotContract> connectionSnapshots = Array.Empty<ConnectionSnapshotContract>();
            try
            {
                connectionSnapshots = await connectionSnapshotProvider.QueryAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is InvalidOperationException or IOException)
            {
                LogConnectionCorrelationUnavailable(exception);
            }

            foreach (var collector in collectors)
            {
                try
                {
                    var rawEvents = await collector.CollectAsync(watermarks[collector], stoppingToken)
                        .ConfigureAwait(false);
                    var persisted = 0;
                    foreach (var rawEvent in rawEvents)
                    {
                        var enrichedEvent = EnrichWithConnection(rawEvent, connectionSnapshots);
                        var evidenceKey = EvidenceKey(enrichedEvent);
                        if (seenEvidence.ContainsKey(evidenceKey))
                        {
                            continue;
                        }

                        var normalized = LoginEventNormalizer.Normalize(idService.NewId, enrichedEvent);
                        await eventStore.AppendAsync(normalized, stoppingToken).ConfigureAwait(false);
                        // 只有持久化成功才确认去重，允许采集器重放暂态写入失败的事件。
                        seenEvidence.TryAdd(evidenceKey, 0);
                        persisted++;
                    }

                    TrimSeenEvidence();
                    // 仅该采集器的整批证据持久化成功后推进水位。中途失败会重读该批，
                    // 已成功写入的部分由内存缓存及 SQLite 幂等检查跳过，避免少计失败。
                    watermarks[collector] = scanStartedAtUtc.Subtract(EvidenceOverlap);
                    LogCollectionCompleted(collector.Name, rawEvents.Count, persisted);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception exception) when (exception is InvalidOperationException or IOException or SqliteException)
                {
                    LogCollectionFailed(collector.Name, exception);
                }
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

    private static string EvidenceKey(RawLoginEventInput rawEvent) =>
        rawEvent.RawEventId is { } rawId
            ? $"{rawEvent.Collector}|{rawId}"
            : string.Join('|',
            rawEvent.OccurredAtUtc.ToUniversalTime().ToString("O"),
            rawEvent.Protocol,
            rawEvent.Success,
            rawEvent.Username,
            rawEvent.RemoteIp,
            rawEvent.RemotePort,
            rawEvent.LocalIp,
            rawEvent.LocalPort,
            rawEvent.Collector);

    private void TrimSeenEvidence()
    {
        if (seenEvidence.Count <= 10_000)
        {
            return;
        }

        foreach (var key in seenEvidence.Keys.Take(2_000))
        {
            seenEvidence.TryRemove(key, out _);
        }
    }

    private static RawLoginEventInput EnrichWithConnection(
        RawLoginEventInput rawEvent,
        IReadOnlyList<ConnectionSnapshotContract> snapshots)
    {
        if (snapshots.Count == 0 || string.IsNullOrWhiteSpace(rawEvent.RemoteIp))
        {
            return rawEvent;
        }

        var candidates = snapshots
            .Where(connection => connection.State.Equals("ESTAB", StringComparison.OrdinalIgnoreCase)
                && string.Equals(connection.RemoteIp, rawEvent.RemoteIp, StringComparison.OrdinalIgnoreCase)
                && (rawEvent.RemotePort is null || connection.RemotePort == rawEvent.RemotePort)
                && (string.IsNullOrWhiteSpace(rawEvent.LocalProcessName)
                    || string.Equals(connection.ProcessName, rawEvent.LocalProcessName, StringComparison.OrdinalIgnoreCase)))
            .OrderByDescending(connection => rawEvent.RemotePort is not null && connection.RemotePort == rawEvent.RemotePort)
            .ThenByDescending(connection => connection.ProcessId == rawEvent.LocalProcessId)
            .ToArray();
        var connection = candidates.FirstOrDefault();
        if (connection is null)
        {
            return rawEvent;
        }

        var processName = rawEvent.LocalProcessName ?? connection.ProcessName;
        var processAvailability = string.IsNullOrWhiteSpace(processName)
            ? rawEvent.ProcessAvailability
            : FieldAvailability.Available;
        return rawEvent with
        {
            LocalIp = rawEvent.LocalIp ?? connection.LocalIp,
            LocalPort = rawEvent.LocalPort ?? connection.LocalPort,
            LocalProcessId = rawEvent.LocalProcessId ?? connection.ProcessId,
            LocalProcessName = processName,
            LocalEndpointAvailability = connection.LocalIp is not null && connection.LocalPort is not null
                ? FieldAvailability.Available
                : rawEvent.LocalEndpointAvailability,
            ProcessAvailability = processAvailability
        };
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "登录采集器 {Collector} 读取 {ReadCount} 条，写入 {PersistedCount} 条")]
    private partial void LogCollectionCompleted(string collector, int readCount, int persistedCount);

    [LoggerMessage(Level = LogLevel.Warning, Message = "登录采集器 {Collector} 本轮失败，后续继续采集")]
    private partial void LogCollectionFailed(string collector, Exception exception);

    [LoggerMessage(Level = LogLevel.Debug, Message = "当前连接查询失败，登录事件本地端点本轮不做关联")]
    private partial void LogConnectionCorrelationUnavailable(Exception exception);
}
