using System.Net;
using System.Text.Json.Serialization;

namespace IpBan.Shared.Logging.Syslog;

public enum SyslogSeverity
{
    Emergency = 0, Alert = 1, Critical = 2, Error = 3,
    Warning = 4, Notice = 5, Informational = 6, Debug = 7
}

public sealed record SyslogSettings(bool Enabled = false, string ConfigRevision = "0", SyslogTarget[]? Targets = null);

public sealed record SyslogTarget(
    string Id, string DeliveryTargetVersion, string Name, string Host, int Port, string Protocol,
    bool Enabled = true, int MaxSeverity = 7, bool IgnoreSslErrors = false, string Framing = "octet");

public sealed record SyslogEvent(
    string EventUid, DateTimeOffset OccurredAtUtc, string ComputerName, string AppName, string SourceProcess,
    int ProcessId, string EventType, SyslogSeverity Severity, string Message, bool Priority = false,
    string? RuntimeLevel = null, string? Category = null, string? Result = null, string? SourceId = null,
    string? RemoteIp = null, string? Actor = null, string? Protocol = null, string? TraceId = null);

public sealed record SyslogProcessStatus(
    string SourceProcess, string? AppliedRevision, string ConfigurationState, SyslogTargetStatus[] Targets,
    long DroppedCount, long PriorityDroppedCount, string? LastError = null, SyslogLocalLogStatus? LocalLog = null);

public sealed record SyslogLocalLogStatus(long WriteFailures, long ArchiveFailures, DateTimeOffset? LastWriteAtUtc);

public sealed record SyslogTargetStatus(
    string TargetId, string DeliveryTargetVersion, string State, int QueuedCount, long QueuedBytes,
    DateTimeOffset? OldestQueuedAtUtc, DateTimeOffset? LastSentAtUtc, DateTimeOffset? LastAcknowledgedAtUtc,
    long FailedCount, long RetryCount, long DroppedCount, long PriorityDroppedCount, string? LastError,
    DateTimeOffset? FirstDroppedAtUtc = null, DateTimeOffset? LastDroppedAtUtc = null,
    long TruncatedCount = 0, DateTimeOffset? FirstPriorityDroppedAtUtc = null, DateTimeOffset? LastPriorityDroppedAtUtc = null);

public interface ISyslogSettingsReader
{
    Task<SyslogSettings> ReadAsync(CancellationToken cancellationToken);
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(SyslogSettings))]
[JsonSerializable(typeof(SyslogEvent))]
[JsonSerializable(typeof(SyslogEvent[]))]
[JsonSerializable(typeof(SyslogProcessStatus))]
public sealed partial class SyslogJsonContext : JsonSerializerContext;

public static class SyslogConfiguration
{
    public const string SettingKey = "syslog.settings";

    public static bool TryNormalize(SyslogSettings candidate, out SyslogSettings normalized, out string message)
    {
        normalized = candidate;
        message = "Syslog 配置无效。";
        if (candidate is null) return false;
        var targets = candidate.Targets ?? [];
        if (targets.Length > 3) { message = "最多配置三个 Syslog 目标。"; return false; }
        var result = new List<SyslogTarget>();
        var destinations = new HashSet<(string, int, string)>();
        foreach (var target in targets)
        {
            if (target is null || target.Name is null || target.Host is null || target.Protocol is null || target.Framing is null)
                return false;
            var name = target.Name.Trim();
            var host = target.Host.Trim().ToLowerInvariant();
            var protocol = target.Protocol.ToLowerInvariant();
            if (name.Length is < 1 or > 64 || name.Any(char.IsControl))
            { message = "目标名称须为 1 到 64 个字符。"; return false; }
            if (host.Length is < 1 or > 253 || host.Any(c => char.IsWhiteSpace(c) || char.IsControl(c)) ||
                host.Contains('%') || Uri.CheckHostName(host) == UriHostNameType.Unknown)
            { message = "服务器地址必须为主机名或 IP 地址，不含协议、路径或账号。"; return false; }
            if (IPAddress.TryParse(host, out var ip))
            {
                if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.Broadcast) ||
                    ip.IsIPv6Multicast || (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && ip.GetAddressBytes()[0] is >= 224 and <= 239))
                { message = "服务器地址必须是单播地址。"; return false; }
                host = ip.ToString();
            }
            else
            {
                host = host.TrimEnd('.');
            }
            if (target.Port is < 1 or > 65535 || protocol is not ("udp" or "tcp" or "tls" or "relp") ||
                target.MaxSeverity is < 0 or > 7 ||
                target.Framing is not ("octet" or "lf") || (protocol != "tcp" && target.Framing == "lf") ||
                (protocol != "tls" && target.IgnoreSslErrors))
            { message = "端口、协议、级别或 TLS 选项无效。"; return false; }
            if (!destinations.Add((host, target.Port, protocol)))
            { message = "不能重复配置同一个 Syslog 目标。"; return false; }
            result.Add(target with { Name = name, Host = host, Protocol = protocol });
        }
        if (candidate.Enabled && !result.Exists(x => x.Enabled))
        { message = "启用 Syslog 前至少启用一个目标。"; return false; }
        normalized = candidate with { Targets = [.. result] };
        message = "";
        return true;
    }
}
