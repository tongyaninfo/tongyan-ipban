using System.Globalization;
using System.Text.Json.Serialization;
using IpBan.Shared.Models;

namespace IpBan.Api.Service.Mcp;

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(McpOverview))]
[JsonSerializable(typeof(McpConnection[]))]
[JsonSerializable(typeof(LoginSessionContract[]))]
[JsonSerializable(typeof(McpLoginEvent[]))]
[JsonSerializable(typeof(FirewallActionContract[]))]
[JsonSerializable(typeof(ManualBanResult))]
[JsonSerializable(typeof(FirewallActionResult))]
[JsonSerializable(typeof(ConnectionTerminationContract))]
[JsonSerializable(typeof(McpAccessListEntry))]
[JsonSerializable(typeof(McpAccessListEntry[]))]
[JsonSerializable(typeof(McpBanPolicy))]
[JsonSerializable(typeof(McpBanPolicy[]))]
[JsonSerializable(typeof(McpLogFile[]))]
[JsonSerializable(typeof(McpBackup[]))]
[JsonSerializable(typeof(McpCertificate[]))]
internal sealed partial class McpBusinessJsonContext : JsonSerializerContext;

internal sealed record McpOverview(DateTimeOffset CheckedAtUtc, string TrendRange, bool Ready,
    string FirewallProvider, FirewallStatus FirewallStatus, long? ActiveConnections, long? ActiveSessions,
    long LoginSuccess, long LoginFailures, long ObserveOnly, long ObserveOnlyWithoutIp, long ActiveBans,
    OverviewTrendPoint[] Trend, OverviewTopSourceIp[] TopSourceIps);

internal sealed record McpConnection(string ConnectionId, string Protocol, string State, string RemoteIp,
    int? RemotePort, string? LocalIp, int? LocalPort, int? ProcessId, string? ProcessName,
    DateTimeOffset ObservedAtUtc, bool CanDisconnect);

internal sealed record McpLoginEvent(string Id, DateTimeOffset OccurredAtUtc, ProtocolKind Protocol, bool Success,
    string? Username, string? RemoteIp, int? RemotePort, string? LocalIp, int? LocalPort, int? LocalProcessId,
    string? LocalProcessName, int? OriginProcessId, string? OriginProcessName,
    EventCompletenessLevel CompletenessLevel, FieldAvailability UsernameAvailability,
    FieldAvailability RemoteIpAvailability, FieldAvailability EndpointAvailability,
    FieldAvailability ProcessAvailability, string Collector, string? RawEventId, string EvidenceSource)
{
    public static McpLoginEvent From(LoginEventContract item) =>
        new(McpIdentifier.Format(item.Id), item.OccurredAtUtc, item.Protocol, item.Success, item.Username, item.RemoteIp,
            item.RemotePort, item.LocalIp, item.LocalPort, item.LocalProcessId, McpIdentifier.FileName(item.LocalProcessName),
            item.OriginProcessId, McpIdentifier.FileName(item.OriginProcessName), item.CompletenessLevel,
            item.UsernameAvailability, item.RemoteIpAvailability, item.EndpointAvailability, item.ProcessAvailability,
            item.Collector, item.RawEventId, item.EvidenceSource.StartsWith("file:", StringComparison.OrdinalIgnoreCase)
                ? "file" : item.EvidenceSource);
}

internal sealed record McpAccessListEntry(string Id, string Address, string EntryType, string Source, string? Reason,
    int Priority, string Status, string? CreatedBy, DateTimeOffset CreatedAtUtc, DateTimeOffset? EffectiveAtUtc,
    DateTimeOffset? ExpiresAtUtc, DateTimeOffset? ReleasedAtUtc)
{
    public static McpAccessListEntry From(AccessListEntryContract item) =>
        new(McpIdentifier.Format(item.Id), item.Address, item.EntryType, item.Source, item.Reason, item.Priority, item.Status,
            item.CreatedBy, item.CreatedAtUtc, item.EffectiveAtUtc, item.ExpiresAtUtc, item.ReleasedAtUtc);
}

internal sealed record McpBanPolicy(string Id, string Name, bool Enabled, int Threshold, int WindowSeconds,
    int ObserveSeconds, int CooldownSeconds, int BanDurationSeconds, string Action, string? Protocol,
    string? Description, int Version, DateTimeOffset CreatedAtUtc, DateTimeOffset UpdatedAtUtc)
{
    public static McpBanPolicy From(BanPolicyContract item) =>
        new(McpIdentifier.Format(item.Id), item.Name, item.Enabled, item.Threshold, item.WindowSeconds,
            item.ObserveSeconds, item.CooldownSeconds, item.BanDurationSeconds, item.Action, item.Protocol,
            item.Description, item.Version, item.CreatedAtUtc, item.UpdatedAtUtc);
}

internal sealed record McpLogFile(string Name, long SizeBytes, DateTimeOffset LastWriteTimeUtc, bool Compressed);
internal sealed record McpBackup(string Id, string BackupKind, long SizeBytes, string? Sha256,
    DateTimeOffset CreatedAtUtc, string Status);
internal sealed record McpCertificate(string Id, string Subject, string? Issuer, string Thumbprint,
    DateTimeOffset NotBeforeUtc, DateTimeOffset NotAfterUtc, bool Active);

internal static class McpIdentifier
{
    public static string Format(long id) => id.ToString(CultureInfo.InvariantCulture);

    // 按采集宿主的分隔符处理，防止 Linux API 转交 Windows 事件时暴露进程路径。
    public static string? FileName(string? name) => name is null ? null : name[(name.LastIndexOfAny(['/', '\\']) + 1)..];
}
