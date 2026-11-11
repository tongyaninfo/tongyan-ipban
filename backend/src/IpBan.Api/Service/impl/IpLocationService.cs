using System.Net;
using System.Diagnostics.Metrics;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading.Channels;
using IpBan.Api.Models;
using IpBan.Shared.Logging.Syslog;

namespace IpBan.Api.Service.impl;

/// <summary>查询只读内存和非阻塞入队；网络访问由独立 Worker 完成，不进入封禁与采集路径。</summary>
public sealed class IpLocationService : IDisposable
{
    private readonly SqliteAdminStore store;
    private readonly TimeProvider clock;
    private readonly SyslogRuntime? syslog;
    private readonly Meter _meter = new("IpBan.IpLocation", "1.0.0");
    private long _completed;
    private long _failed;
    private long _rejected;
    private long _active;
    public const string SettingKey = "ip-location";
    public const int QueueCapacity = 512;
    public const int CacheCapacity = 10_000;
    public static readonly string[] Databases = ["CZ88", "ip2location", "ip2region", "dbip", "ipinfo", "geolite2"];
    private readonly object _sync = new();
    private readonly SemaphoreSlim _configurationGate = new(1, 1);
    private readonly Channel<WorkItem> _queue = Channel.CreateBounded<WorkItem>(new BoundedChannelOptions(QueueCapacity)
    {
        FullMode = BoundedChannelFullMode.Wait, SingleWriter = false, SingleReader = false, AllowSynchronousContinuations = false
    });
    private readonly Dictionary<string, CacheItem> _cache = new(StringComparer.Ordinal);
    private readonly HashSet<string> _pending = new(StringComparer.Ordinal);
    private Generation _generation = new(new IpLocationSettings());
    private bool _initialized;

    public IpLocationService(SqliteAdminStore store, TimeProvider clock, SyslogRuntime? syslog = null)
    {
        this.store = store;
        this.clock = clock;
        this.syslog = syslog;
        _meter.CreateObservableGauge("ipban.ip_location.queue", () => _queue.Reader.Count);
        _meter.CreateObservableGauge("ipban.ip_location.cache", () => { lock (_sync) return _cache.Count; });
        _meter.CreateObservableGauge("ipban.ip_location.active", () => Interlocked.Read(ref _active));
        _meter.CreateObservableCounter("ipban.ip_location.completed", () => Interlocked.Read(ref _completed));
        _meter.CreateObservableCounter("ipban.ip_location.failed", () => Interlocked.Read(ref _failed));
        _meter.CreateObservableCounter("ipban.ip_location.rejected", () => Interlocked.Read(ref _rejected));
    }

    public async Task<IpLocationSettings> GetSettingsAsync(CancellationToken cancellationToken)
    {
        await _configurationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!_initialized)
            {
                var json = await store.GetIpLocationSettingsAsync(cancellationToken).ConfigureAwait(false);
                IpLocationSettings? settings;
                try { settings = json is null ? new IpLocationSettings()
                    : JsonSerializer.Deserialize(json, IpLocationJsonContext.Default.IpLocationSettings); }
                catch (JsonException exception) { throw new InvalidDataException("IP 归属地配置无效。", exception); }
                if (settings is null || !TryValidate(settings, out var normalized, out _))
                    throw new InvalidDataException("IP 归属地配置无效。");
                ReplaceGeneration(normalized);
                _initialized = true;
            }
            lock (_sync) return _generation.Settings;
        }
        finally { _configurationGate.Release(); }
    }

    public async Task<IpLocationSettings> UpdateSettingsAsync(IpLocationSettings settings, string actor, string? remoteIp, CancellationToken cancellationToken)
    {
        if (!TryValidate(settings, out var normalized, out var message)) throw new ArgumentException(message);
        await _configurationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await store.SaveIpLocationSettingsAsync(JsonSerializer.Serialize(normalized, IpLocationJsonContext.Default.IpLocationSettings),
                actor, remoteIp, cancellationToken).ConfigureAwait(false);
            ReplaceGeneration(normalized);
            _initialized = true;
            return normalized;
        }
        finally { _configurationGate.Release(); }
    }

    public IpLocationBatchResult Lookup(IReadOnlyList<string> ips)
    {
        lock (_sync)
        {
            var generation = _generation;
            var now = clock.GetUtcNow();
            var results = new IpLocationResult[ips.Count];
            for (var index = 0; index < ips.Count; index++)
            {
                var original = ips[index] ?? string.Empty;
                var input = original.Trim();
                if (!generation.Settings.Enabled)
                {
                    results[index] = new(original, "disabled");
                    continue;
                }
                var (ip, status) = Classify(input);
                if (status is not null) { results[index] = new(original, status); continue; }
                if (_cache.TryGetValue(ip, out var cached))
                {
                    if (cached.ExpiresAt > now) { results[index] = cached.Result with { Ip = original }; continue; }
                    _cache.Remove(ip);
                }
                if (_pending.Contains(ip)) { results[index] = new(original, "queued"); continue; }
                // 队列满直接返回 Busy；不让管理请求等待工作槽位。
                if (_queue.Writer.TryWrite(new WorkItem(ip, generation)))
                {
                    _pending.Add(ip);
                    results[index] = new(original, "queued");
                }
                else
                {
                    Interlocked.Increment(ref _rejected);
                    results[index] = new(original, "busy");
                }
            }
            return new(generation.Settings.Enabled, generation.Revision, results);
        }
    }

    public async Task ProcessQueueAsync(IIPLocation provider, CancellationToken stoppingToken)
    {
        await foreach (var item in _queue.Reader.ReadAllAsync(stoppingToken).ConfigureAwait(false))
        {
            lock (_sync)
                if (!ReferenceEquals(item.Generation, _generation) || !item.Generation.Settings.Enabled) continue;
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken, item.Generation.Token);
            IpLocationResult result;
            Interlocked.Increment(ref _active);
            try { result = await provider.ResolveAsync(item.Ip, item.Generation.Settings, cancellation.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { continue; }
            catch (Exception) { result = new(item.Ip, "failed", Database: item.Generation.Settings.Database); }
            finally { Interlocked.Decrement(ref _active); }
            Interlocked.Increment(ref _completed);
            var failed = result.Status is "timeout" or "failed";
            if (failed) Interlocked.Increment(ref _failed);
            bool stateChanged;
            lock (_sync)
            {
                if (!ReferenceEquals(item.Generation, _generation) || stoppingToken.IsCancellationRequested) continue;
                stateChanged = item.Generation.Unavailable != failed;
                item.Generation.Unavailable = failed;
                _pending.Remove(item.Ip);
                if (_cache.Count >= CacheCapacity)
                {
                    // 缓存满时只淘汰一项，避免每次查询做全量扫描。
                    _cache.Remove(_cache.Keys.First());
                }
                _cache[item.Ip] = new(result, clock.GetUtcNow().Add(result.Status == "resolved" ? TimeSpan.FromHours(24) : TimeSpan.FromMinutes(1)));
            }
            if (stateChanged)
                syslog?.Publish("ipban-geoip", failed ? "geoip.unavailable" : "geoip.recovered",
                    failed ? SyslogSeverity.Warning : SyslogSeverity.Notice,
                    failed ? "IP 归属地服务查询失败。" : "IP 归属地服务查询已恢复。", result: result.Status);
        }
    }

    private void ReplaceGeneration(IpLocationSettings settings)
    {
        Generation previous;
        lock (_sync)
        {
            previous = _generation;
            _generation = new(settings);
            _cache.Clear();
            _pending.Clear();
            while (_queue.Reader.TryRead(out _)) { }
        }
        // 在锁外取消，避免 HttpClient 的取消回调与结果写入互相等待。
        previous.Cancellation.Cancel();
        previous.Cancellation.Dispose();
    }

    public void Dispose()
    {
        _queue.Writer.TryComplete();
        _generation.Cancellation.Cancel();
        _generation.Cancellation.Dispose();
        _configurationGate.Dispose();
        _meter.Dispose();
    }

    public static bool TryValidate(IpLocationSettings settings, out IpLocationSettings normalized, out string message)
    {
        normalized = settings;
        message = "请检查协议、地址、端口、数据库和超时时间。";
        if (settings.Protocol is not ("http" or "https") || string.IsNullOrWhiteSpace(settings.Host)
            || settings.Host.Length > 253 || settings.Host != settings.Host.Trim()
            || settings.Host.Any(character => char.IsControl(character) || char.IsWhiteSpace(character))
            || settings.Host.IndexOfAny(['/', '\\', '@', '?', '#', '%']) >= 0
            || Uri.CheckHostName(settings.Host) == UriHostNameType.Unknown
            || settings.Port is < 1 or > 65535 || !double.IsFinite(settings.TimeoutSeconds)
            || settings.TimeoutSeconds is < 0.1 or > 30) return false;
        var database = Databases.FirstOrDefault(value => value.Equals(settings.Database, StringComparison.OrdinalIgnoreCase));
        if (database is null) return false;
        normalized = settings with { Host = settings.Host.ToLowerInvariant(), Database = database };
        return true;
    }

    private static (string Ip, string? Status) Classify(string input)
    {
        if (input.Contains('/'))
        {
            var parts = input.Split('/');
            return (input, parts.Length == 2 && IPAddress.TryParse(parts[0], out var network)
                && int.TryParse(parts[1], out var prefix) && prefix >= 0
                && prefix <= (network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128) ? "network" : "invalid");
        }
        if (input.Contains('%') || !IPAddress.TryParse(input, out var address)) return (input, "invalid");
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        var canonical = address.ToString();
        var bytes = address.GetAddressBytes();
        if (IPAddress.IsLoopback(address)) return (canonical, "private");
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            if (bytes[0] == 10 || bytes[0] == 172 && bytes[1] is >= 16 and <= 31 || bytes[0] == 192 && bytes[1] == 168
                || bytes[0] == 169 && bytes[1] == 254 || bytes[0] == 100 && bytes[1] is >= 64 and <= 127)
                return (canonical, "private");
            if (bytes[0] == 0 || bytes[0] >= 224 || bytes[0] == 192 && bytes[1] == 0 && bytes[2] is 0 or 2
                || bytes[0] == 192 && bytes[1] == 88 && bytes[2] == 99
                || bytes[0] == 198 && (bytes[1] is 18 or 19 || bytes[1] == 51 && bytes[2] == 100)
                || bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113) return (canonical, "reserved");
        }
        else
        {
            if (address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || (bytes[0] & 0xfe) == 0xfc) return (canonical, "private");
            if ((bytes[0] & 0xe0) != 0x20 || bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8
                || bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0 && bytes[3] == 2 && bytes[4] == 0 && bytes[5] == 0
                || bytes[0] == 0x3f && bytes[1] == 0xff && (bytes[2] & 0xf0) == 0)
                return (canonical, "reserved");
        }
        return (canonical, null);
    }

    private sealed class Generation
    {
        public bool Unavailable { get; set; }
        public Generation(IpLocationSettings settings)
        {
            Settings = settings;
            Token = Cancellation.Token;
        }
        public IpLocationSettings Settings { get; }
        public string Revision { get; } = Guid.NewGuid().ToString("N");
        public CancellationTokenSource Cancellation { get; } = new();
        public CancellationToken Token { get; }
    }
    private sealed record WorkItem(string Ip, Generation Generation);
    private sealed record CacheItem(IpLocationResult Result, DateTimeOffset ExpiresAt);
}
