using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace IpBan.Shared.Logging.Syslog;

/// <summary>日志生产者只进有界队列；磁盘、重试和目标连接由后台任务管理。</summary>
public sealed class SyslogRuntime : BackgroundService
{
    private const int MemoryCount = 10000;
    private const long MemoryBytes = 32 * 1024 * 1024;
    private readonly Lock gate = new();
    private readonly IServiceProvider services;
    private readonly FileLoggerProvider? local;
    private readonly SyslogDiskSpool spool;
    private readonly string sourceProcess;
    private readonly string computerName;
    private readonly LinkedList<Pending> urgent = new();
    private readonly LinkedList<Pending> normal = new();
    private readonly LinkedList<Pending> diagnostics = new();
    private readonly Dictionary<SyslogDiskSpool.Destination, Metrics> metrics = [];
    private SyslogDiskSpool.Segment[] disk = [];
    private long urgentBytes;
    private long normalBytes;
    private long diagnosticsBytes;
    private int ingressUrgentRun;
    private long dropped;
    private long priorityDropped;
    private string configurationState = "loading";
    private string? processError;
    private SyslogSettings? settings;
    private long generation;
    private int disposed;
    private CancellationTokenSource delivery = new();

    internal SyslogRuntime(string process, string directory, string? host, IServiceProvider services, FileLoggerProvider? local)
    {
        sourceProcess = process;
        computerName = SyslogEventCatalog.Clean(string.IsNullOrWhiteSpace(host) ? Environment.MachineName : host.Trim(), 256)!;
        this.services = services;
        this.local = local;
        spool = new SyslogDiskSpool(Path.Combine(directory, "syslog-spool", process));
    }

    public SyslogEvent CreateEvent(string appName, string eventType, SyslogSeverity severity, string message,
        bool priority = false, string? result = null, string? sourceId = null, string? remoteIp = null, string? actor = null,
        string? protocol = null, string? traceId = null, DateTimeOffset? occurredAtUtc = null)
    {
        var id = SyslogEventCatalog.Clean(sourceId, 96);
        return new(
            id is null ? Guid.NewGuid().ToString("N") :
                Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes($"{computerName}:{sourceProcess}:{eventType}:{id}")).AsSpan(0, 16)),
            occurredAtUtc ?? DateTimeOffset.UtcNow, computerName, appName, sourceProcess, Environment.ProcessId, eventType, severity,
            SyslogEventCatalog.Clean(message, 1024)!, priority || severity == SyslogSeverity.Emergency,
            Result: SyslogEventCatalog.Clean(result, 80), SourceId: id,
            RemoteIp: IPAddress.TryParse(remoteIp, out var address) ? address.ToString() :
                IPNetwork.TryParse(remoteIp, out var network) ? network.ToString() : null,
            Actor: SyslogEventCatalog.Clean(actor, 128), Protocol: SyslogEventCatalog.Clean(protocol, 32),
            TraceId: SyslogEventCatalog.Clean(traceId, 128));
    }

    public void Publish(string appName, string eventType, SyslogSeverity severity, string message,
        bool priority = false, string? result = null, string? sourceId = null, string? remoteIp = null, string? actor = null,
        string? protocol = null, string? traceId = null, DateTimeOffset? occurredAtUtc = null)
    {
        Publish(CreateEvent(appName, eventType, severity, message, priority, result, sourceId, remoteIp, actor, protocol, traceId, occurredAtUtc));
    }

    public void Publish(SyslogEvent entry)
    {
        local?.WriteSyslogEvent(entry);
        Enqueue(entry);
    }

    internal bool IsEnabled()
    {
        lock (gate) return settings?.Enabled != false;
    }

    internal void RuntimeLog<TState>(string category, LogLevel level, EventId eventId, TState state, Exception? exception)
    {
        var module = SyslogEventCatalog.Module(category);
        var message = SyslogEventCatalog.RuntimeMessage(category, level, state, exception);
        Enqueue(CreateEvent(module, "runtime." + eventId.Id.ToString(CultureInfo.InvariantCulture),
            SyslogEventCatalog.Severity(level), message) with { RuntimeLevel = level.ToString(), Category = category });
    }

    private static SyslogDiskSpool.Destination[] Select(SyslogSettings configuration, SyslogEvent entry) =>
        configuration.Enabled
            ? (configuration.Targets ?? []).Where(x => x.Enabled && (entry.Priority || (int)entry.Severity <= x.MaxSeverity))
                .Select(SyslogDiskSpool.Destination.From).ToArray()
            : [];

    private static bool IsDiagnostic(SyslogEvent entry) => !entry.Priority &&
        (entry.Severity == SyslogSeverity.Debug || (entry.AppName == "ipban-http" && entry.Severity == SyslogSeverity.Informational));

    private void Enqueue(SyslogEvent entry)
    {
        lock (gate)
        {
            var targets = settings is null ? null : Select(settings, entry);
            if (targets is { Length: 0 }) return;
            // 保守计入对象、字符串和目标快照开销。
            var bytes = 1024 + 2 * (entry.Message.Length + entry.EventUid.Length + entry.ComputerName.Length +
                (entry.Category?.Length ?? 0) + (entry.Actor?.Length ?? 0) + (entry.TraceId?.Length ?? 0) +
                (entry.SourceId?.Length ?? 0) + (entry.Result?.Length ?? 0));
            if (entry.Priority)
            {
                while (normal.Count + diagnostics.Count > 0 && (urgent.Count + normal.Count + diagnostics.Count >= MemoryCount || urgentBytes + normalBytes + bytes > MemoryBytes))
                    EvictOrdinary();
                if (urgent.Count + normal.Count + diagnostics.Count >= MemoryCount || urgentBytes + normalBytes + bytes > MemoryBytes)
                { Drop(entry.Priority, 1, targets, "MEMORY_FULL"); return; }
                urgent.AddLast(new Pending(entry, targets, bytes));
                urgentBytes += bytes;
            }
            else
            {
                var diagnostic = IsDiagnostic(entry);
                if (diagnostic && (diagnostics.Count >= MemoryCount / 8 || diagnosticsBytes + bytes > MemoryBytes / 8))
                { Drop(false, 1, targets, "DIAGNOSTIC_BUFFER_FULL"); return; }
                while (!diagnostic && diagnostics.Count > 0 &&
                    (normal.Count + diagnostics.Count >= MemoryCount / 2 || normalBytes + bytes > MemoryBytes / 2 ||
                     urgent.Count + normal.Count + diagnostics.Count >= MemoryCount || urgentBytes + normalBytes + bytes > MemoryBytes))
                    EvictOrdinary();
                if (normal.Count + diagnostics.Count >= MemoryCount / 2 || normalBytes + bytes > MemoryBytes / 2 ||
                    normal.Count + diagnostics.Count + urgent.Count >= MemoryCount || normalBytes + urgentBytes + bytes > MemoryBytes)
                { Drop(false, 1, targets, "MEMORY_FULL"); return; }
                (diagnostic ? diagnostics : normal).AddLast(new Pending(entry, targets, bytes));
                if (diagnostic) diagnosticsBytes += bytes;
                normalBytes += bytes;
            }
        }
    }

    private void EvictOrdinary()
    {
        var from = diagnostics.Count > 0 ? diagnostics : normal;
        var first = from.First!.Value;
        from.RemoveFirst();
        if (from == diagnostics) diagnosticsBytes -= first.Bytes;
        normalBytes -= first.Bytes;
        Drop(false, 1, first.Targets, "MEMORY_FULL");
    }

    public void Apply(SyslogSettings configuration) => ApplyCore(configuration, null);

    private void ApplyCore(SyslogSettings configuration, long? expectedGeneration)
    {
        if (!SyslogConfiguration.TryNormalize(configuration, out var normalized, out _) ||
            !SyslogDiskSpool.SafeKey(normalized.ConfigRevision) ||
            normalized.Targets!.Any(x => !SyslogDiskSpool.SafeKey(x.Id) || !SyslogDiskSpool.SafeKey(x.DeliveryTargetVersion)) ||
            normalized.Targets!.Select(x => x.Id).Distinct(StringComparer.Ordinal).Count() != normalized.Targets!.Length)
            throw new InvalidDataException("已保存的 Syslog 配置不合法。");

        lock (gate)
        {
            if (expectedGeneration.HasValue && generation != expectedGeneration.Value) return;
            if (settings?.ConfigRevision == normalized.ConfigRevision && configurationState == "ready") return;
            ReplaceDelivery();
            settings = normalized;
            configurationState = "ready";
            generation++;
        }
    }

    private void ReplaceDelivery()
    {
        var prior = delivery;
        delivery = new CancellationTokenSource();
        prior.Cancel();
        prior.Dispose();
    }

    public SyslogProcessStatus Snapshot()
    {
        lock (gate)
        {
            var current = (settings?.Targets ?? []).ToDictionary(SyslogDiskSpool.Destination.From);
            var queued = disk.ToLookup(x => x.Target);
            var statuses = current.Keys.Concat(queued.Select(x => x.Key)).Distinct().Select(key =>
            {
                current.TryGetValue(key, out var target);
                metrics.TryGetValue(key, out var health);
                var state = configurationState != "ready" ? "unknown" :
                    target is null ? "paused" : !target.Enabled || settings?.Enabled != true ? "disabled" :
                    health?.LastFailure is not null ? "retrying" :
                    health?.LastSent is not null ? "sent" : "ready";
                var rows = queued[key];
                return new SyslogTargetStatus(key.Id, key.Version, state, rows.Sum(x => x.Count - x.Offset),
                    rows.Sum(x => x.Bytes), rows.MinBy(x => x.Created)?.Created, health?.LastSent, health?.LastAck,
                    health?.Failed ?? 0, health?.Retries ?? 0, health?.Dropped ?? 0, health?.PriorityDropped ?? 0,
                    health?.LastFailure ?? health?.LastDropReason, health?.FirstDropped, health?.LastDropped,
                    health?.Truncated ?? 0, health?.FirstPriorityDropped, health?.LastPriorityDropped);
            }).ToArray();
            return new(sourceProcess, settings?.ConfigRevision, configurationState, statuses, dropped, priorityDropped, processError,
                local?.GetStatus());
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var lifecycle = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        var refresh = RefreshAsync(lifecycle.Token);
        try { await DispatchAsync(lifecycle.Token).ConfigureAwait(false); }
        finally
        {
            await lifecycle.CancelAsync().ConfigureAwait(false);
            await refresh.ConfigureAwait(false);
        }
    }

    private async Task RefreshAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(3));
        try
        {
            do
            {
                long before;
                lock (gate) before = generation;
                try
                {
                    // 延迟取配置读取器，避免读取器引用日志或业务存储时形成宿主 DI 环。
                    var configuration = await services.GetRequiredService<ISyslogSettingsReader>().ReadAsync(stoppingToken).ConfigureAwait(false);
                    ApplyCore(configuration, before);
                }
                catch (Exception error) when (error is not OperationCanceledException || !stoppingToken.IsCancellationRequested)
                {
                    lock (gate)
                    {
                        if (generation == before && configurationState != "unknown")
                        {
                            configurationState = "unknown";
                            ReplaceDelivery();
                            generation++;
                        }
                    }
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }

    private async Task DispatchAsync(CancellationToken stoppingToken)
    {
        var senders = new Dictionary<SyslogDiskSpool.Destination, Sender>();
        var opened = false;
        var nextOpen = DateTimeOffset.MinValue;
        var nextPrune = DateTimeOffset.MinValue;
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(150));
        try
        {
            do
            {
                var now = DateTimeOffset.UtcNow;
                if (!opened && now >= nextOpen)
                {
                    try { spool.Open(); opened = true; lock (gate) processError = null; }
                    catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                    { lock (gate) processError = "SPOOL_UNAVAILABLE"; nextOpen = now.AddSeconds(10); }
                }
                if (!opened) continue;

                SyslogTarget[] targets;
                CancellationToken configurationToken;
                lock (gate)
                {
                    targets = configurationState == "ready" && settings?.Enabled == true
                        ? (settings.Targets ?? []).Where(x => x.Enabled).ToArray() : [];
                    configurationToken = delivery.Token;
                }

                foreach (var key in senders.Keys.ToArray())
                {
                    var sender = senders[key];
                    if (sender.Work is { IsCompleted: false }) continue;
                    if (sender.Work is not null) await sender.Work.ConfigureAwait(false);
                    if (targets.Any(x => SyslogDiskSpool.Destination.From(x) == key)) continue;
                    await sender.DisposeAsync().ConfigureAwait(false);
                    senders.Remove(key);
                }

                if (now >= nextPrune)
                {
                    foreach (var segment in spool.Snapshot().Where(x => now - x.Created >= TimeSpan.FromHours(24) &&
                                 (!senders.TryGetValue(x.Target, out var sender) || sender.Work is not { IsCompleted: false })))
                        Discard(segment, "QUEUE_EXPIRED");
                    nextPrune = now.AddSeconds(30);
                }

                Drain(now, 256);
                foreach (var target in targets)
                {
                    var key = SyslogDiskSpool.Destination.From(target);
                    if (!senders.TryGetValue(key, out var sender))
                    {
                        if (senders.Count >= 3) continue;
                        sender = new Sender(target);
                        senders.Add(key, sender);
                    }
                    if (sender.Work is { IsCompleted: false } || sender.NextAttempt > now) continue;
                    // 网络任务独立，慢目标不能阻塞其他目标的调度。
                    sender.Work = SendAsync(key, sender, configurationToken, stoppingToken);
                }
                var snapshot = spool.Snapshot();
                lock (gate)
                {
                    disk = snapshot;
                    if (metrics.Count > 64)
                    {
                        var retained = snapshot.Select(x => x.Target).Concat((settings?.Targets ?? []).Select(SyslogDiskSpool.Destination.From)).ToHashSet();
                        foreach (var key in metrics.Keys.Where(x => !retained.Contains(x)).ToArray()) metrics.Remove(key);
                    }
                }
            } while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally
        {
            foreach (var sender in senders.Values)
            {
                if (sender.Work is not null) await sender.Work.ConfigureAwait(false);
                await sender.DisposeAsync().ConfigureAwait(false);
            }
            if (opened)
            {
                // 退出仅写一批已经接纳的事件，不等待远端恢复。
                Drain(DateTimeOffset.UtcNow, 256);
                spool.Close();
            }
        }
    }

    private void Drain(DateTimeOffset now, int limit)
    {
        var batches = new Dictionary<(SyslogDiskSpool.Destination, bool, bool), List<SyslogEvent>>();
        lock (gate)
        {
            if (settings is null) return;
            while (limit-- > 0 && urgent.Count + normal.Count + diagnostics.Count > 0)
            {
                var from = urgent.Count > 0 && (ingressUrgentRun < 8 || normal.Count + diagnostics.Count == 0)
                    ? urgent : normal.Count > 0 ? normal : diagnostics;
                var item = from.First!.Value;
                from.RemoveFirst();
                if (item.Entry.Priority) urgentBytes -= item.Bytes; else normalBytes -= item.Bytes;
                var diagnostic = from == diagnostics;
                if (diagnostic) diagnosticsBytes -= item.Bytes;
                ingressUrgentRun = item.Entry.Priority ? Math.Min(8, ingressUrgentRun + 1) : 0;
                foreach (var target in item.Targets ?? Select(settings, item.Entry))
                {
                    var key = (target, item.Entry.Priority, diagnostic);
                    if (!batches.TryGetValue(key, out var batch)) batches[key] = batch = [];
                    batch.Add(item.Entry);
                }
            }
        }
        foreach (var ((target, priority, diagnostic), events) in batches)
        {
            foreach (var batch in events.Chunk(64))
            {
                string? reason = null;
                try
                {
                    if (!spool.Append(target, priority, diagnostic, batch, now)) reason = "SPOOL_FULL";
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                { reason = "SPOOL_WRITE_FAILED"; }
                if (reason is not null)
                    lock (gate) Drop(priority, batch.Length, [target], reason);
            }
        }
    }

    private async Task SendAsync(SyslogDiskSpool.Destination key, Sender sender,
        CancellationToken configurationToken, CancellationToken stoppingToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(configurationToken, stoppingToken);
        try
        {
            for (var i = 0; i < 8; i++)
            {
                linked.Token.ThrowIfCancellationRequested();
                var segment = sender.UrgentRun >= 8
                    ? spool.First(key, false) ?? spool.First(key, true)
                    : spool.First(key, true) ?? spool.First(key, false);
                if (segment is null) return;
                if (DateTimeOffset.UtcNow - segment.Created >= TimeSpan.FromHours(24)) { Discard(segment, "QUEUE_EXPIRED"); continue; }
                if (sender.CachedId != segment.Id)
                {
                    try { sender.Events = spool.Read(segment); sender.CachedId = segment.Id; }
                    catch (Exception e) when (e is InvalidDataException or JsonException)
                    { Discard(segment, "SPOOL_CORRUPT"); continue; }
                }
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(linked.Token);
                timeout.CancelAfter(TimeSpan.FromSeconds(5));
                bool ack;
                try { ack = await sender.Transport.SendAsync(sender.Events![segment.Offset], timeout.Token).ConfigureAwait(false); }
                catch (ArgumentException)
                {
                    // 单条格式异常不能堵住后续安全事件。
                    spool.Advance(segment);
                    lock (gate) Drop(segment.Priority, 1, [key], "FRAME_INVALID");
                    continue;
                }
                spool.Advance(segment);
                sender.UrgentRun = segment.Priority ? Math.Min(8, sender.UrgentRun + 1) : 0;
                sender.ConsecutiveFailures = 0;
                lock (gate)
                {
                    var health = GetMetrics(key);
                    health.LastSent = DateTimeOffset.UtcNow;
                    if (ack) health.LastAck = health.LastSent;
                    if (sender.Transport.LastSendTruncated) health.Truncated++;
                    health.LastFailure = null;
                }
            }
        }
        catch (OperationCanceledException) when (linked.IsCancellationRequested)
        {
            await sender.ResetAsync().ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or SocketException or OperationCanceledException or TimeoutException or System.Security.Authentication.AuthenticationException or UnauthorizedAccessException)
        {
            await sender.ResetAsync().ConfigureAwait(false);
            if (linked.IsCancellationRequested) return;
            var attempts = sender.ConsecutiveFailures = Math.Min(sender.ConsecutiveFailures + 1, 7);
            sender.NextAttempt = DateTimeOffset.UtcNow.AddMilliseconds(Math.Min(60000, 1000 * (1 << (attempts - 1))) + Random.Shared.Next(0, 350));
            lock (gate)
            {
                var health = GetMetrics(key);
                health.Failed++;
                health.Retries++;
                health.LastFailure = e switch
                {
                    OperationCanceledException or TimeoutException => "SEND_TIMEOUT",
                    System.Security.Authentication.AuthenticationException => "TLS_FAILED",
                    SocketException => "NETWORK_FAILED",
                    _ => "DELIVERY_FAILED"
                };
            }
        }
    }

    private void Discard(SyslogDiskSpool.Segment segment, string reason)
    {
        try { spool.Remove(segment); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        { lock (gate) processError = "SPOOL_CLEANUP_FAILED"; return; }
        lock (gate) Drop(segment.Priority, segment.Count - segment.Offset, [segment.Target], reason);
    }

    private Metrics GetMetrics(SyslogDiskSpool.Destination key)
    {
        if (!metrics.TryGetValue(key, out var value)) metrics.Add(key, value = new Metrics());
        return value;
    }

    // 调用者持有 gate；过程计数与各目标计数分开记录。
    private void Drop(bool priority, int count, SyslogDiskSpool.Destination[]? targets, string reason)
    {
        dropped += count;
        if (priority) priorityDropped += count;
        foreach (var target in targets ?? [])
        {
            var health = GetMetrics(target);
            health.Dropped += count;
            health.LastDropReason = reason;
            var now = DateTimeOffset.UtcNow;
            health.FirstDropped ??= now;
            health.LastDropped = now;
            if (priority)
            {
                health.PriorityDropped += count;
                health.FirstPriorityDropped ??= now;
                health.LastPriorityDropped = now;
            }
        }
    }

    private sealed record Pending(SyslogEvent Entry, SyslogDiskSpool.Destination[]? Targets, int Bytes);
    private sealed class Metrics
    {
        public long Failed, Retries, Dropped, PriorityDropped, Truncated;
        public DateTimeOffset? LastSent, LastAck, FirstDropped, LastDropped;
        public DateTimeOffset? FirstPriorityDropped, LastPriorityDropped;
        public string? LastFailure, LastDropReason;
    }

    private sealed class Sender(SyslogTarget target) : IAsyncDisposable
    {
        public SyslogTransport Transport { get; private set; } = new(target);
        public Task? Work;
        public DateTimeOffset NextAttempt;
        public int ConsecutiveFailures, UrgentRun;
        public Guid CachedId;
        public SyslogEvent[]? Events;
        public async ValueTask ResetAsync()
        {
            await Transport.DisposeAsync().ConfigureAwait(false);
            Transport = new SyslogTransport(target);
        }
        public ValueTask DisposeAsync() => Transport.DisposeAsync();
    }

    public override void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        base.Dispose();
        if (ExecuteTask is null or { IsCompleted: true })
        {
            delivery.Dispose();
            spool.Dispose();
        }
        else
        {
            _ = ExecuteTask.ContinueWith(_ =>
            {
                delivery.Dispose();
                spool.Dispose();
            }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }
    }
}

[ProviderAlias("IpBanSyslog")]
internal sealed class SyslogLoggerProvider(SyslogRuntime runtime) : ILoggerProvider
{
    public ILogger CreateLogger(string categoryName) => new RuntimeLogger(runtime, categoryName);
    public void Dispose() { }

    private sealed class RuntimeLogger(SyslogRuntime runtime, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None && runtime.IsEnabled();
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (IsEnabled(logLevel)) runtime.RuntimeLog(category, logLevel, eventId, state, exception);
        }
    }
}

public static class SyslogServiceCollectionExtensions
{
    public static IServiceCollection AddIpBanSyslog(this IServiceCollection services, ILoggingBuilder logging,
        string sourceProcess, string dataDirectory, string? computerName = null)
    {
        services.AddSingleton(sp => new SyslogRuntime(sourceProcess, dataDirectory, computerName,
            sp, sp.GetService<FileLoggerProvider>()));
        services.AddSingleton<ILoggerProvider>(sp => new SyslogLoggerProvider(sp.GetRequiredService<SyslogRuntime>()));
        services.AddHostedService(sp => sp.GetRequiredService<SyslogRuntime>());
        return services;
    }

}
