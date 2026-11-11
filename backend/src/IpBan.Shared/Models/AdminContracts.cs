namespace IpBan.Shared.Models;

public sealed record OverviewTrendPoint(
    string Time,
    DateTimeOffset AtUtc,
    long Success,
    long Failure,
    long ObserveOnly);

public sealed record OverviewTopSourceIp(string Ip, long Count, long Success, long Failure, long ObserveOnly);

public sealed record OverviewProtocolCount(string Protocol, long Count);

public sealed record OverviewRecentEvent(
    DateTimeOffset OccurredAtUtc,
    string Protocol,
    bool Success,
    string? RemoteIp,
    string? Username,
    int? RemotePort,
    string? LocalIp,
    int? LocalPort,
    string? ProcessName,
    string CompletenessLevel,
    string Collector,
    string? EvidenceSource);

public sealed record OverviewStorageContract(
    long DatabaseBytes,
    long LogBytes,
    long ArchiveBytes,
    DateTimeOffset? OldestEventUtc,
    DateTimeOffset? LastWriteUtc,
    DateTimeOffset? LastRotationUtc,
    DateTimeOffset? LastBackupUtc);

public sealed record OverviewHostContract(
    string OsVersion,
    string ComputerName,
    string[] IpAddresses,
    DateTimeOffset? StartedAtUtc);

public sealed record OverviewContract(
    DateTimeOffset CheckedAtUtc,
    string TrendRange,
    bool Ready,
    string FirewallProvider,
    FirewallStatus FirewallStatus,
    long ActiveConnections,
    long ActiveSessions,
    long TodayLoginSuccess,
    long TodayLoginFailures,
    long TodayObserveOnly,
    long ActiveBans,
    long ExpiringBans,
    OverviewTrendPoint[] Trend,
    OverviewTopSourceIp[] TopSourceIps,
    OverviewProtocolCount[] Protocols,
    OverviewRecentEvent[] RecentEvents,
    OverviewStorageContract Storage,
    DateTimeOffset? LastLoginEventUtc,
    DateTimeOffset? LastAuditUtc)
{
    public OverviewHostContract? Host { get; init; }
    public long ObserveOnlyWithoutIp { get; init; }
}

public sealed record UserSummaryContract(
    long Id,
    string Username,
    string DisplayName,
    bool Enabled,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? LastLoginAtUtc);

public sealed record SetupStatusContract(bool Initialized);

public sealed record SystemSettingContract(
    string Key,
    string? Value,
    bool IsSecret,
    DateTimeOffset UpdatedAtUtc,
    string? UpdatedBy);

public sealed record CertificateMetadataContract(
    long Id,
    string CertificatePath,
    string Subject,
    string? Issuer,
    string Thumbprint,
    DateTimeOffset NotBeforeUtc,
    DateTimeOffset NotAfterUtc,
    DateTimeOffset UploadedAtUtc,
    bool Active);

public sealed record AuditRecordContract(
    long Id,
    DateTimeOffset OccurredAtUtc,
    string Action,
    string Category,
    string? ActorUsername,
    string? Target,
    string? DetailJson,
    string? RemoteIp,
    bool Success);

public sealed record BackupRecordContract(
    long Id,
    string BackupKind,
    string BackupPath,
    long SizeBytes,
    string? Sha256,
    DateTimeOffset CreatedAtUtc,
    string Status,
    string? ErrorMessage);

public sealed record FirewallActionContract(
    [property: System.Text.Json.Serialization.JsonNumberHandling(System.Text.Json.Serialization.JsonNumberHandling.WriteAsString | System.Text.Json.Serialization.JsonNumberHandling.AllowReadingFromString)]
    long Id,
    DateTimeOffset CreatedAtUtc,
    string SourceIp,
    string Action,
    string Status,
    string Provider,
    string? ErrorCode,
    string? ErrorMessage,
    DateTimeOffset? CompletedAtUtc,
    bool CanUnban = false,
    string? CurrentStatus = null);

public sealed record AccessListEntryContract(
    long Id,
    string Address,
    string EntryType,
    string Source,
    string? Reason,
    int Priority,
    string Status,
    string? CreatedBy,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? EffectiveAtUtc,
    DateTimeOffset? ExpiresAtUtc,
    DateTimeOffset? ReleasedAtUtc);

public sealed record BanPolicyContract(
    long Id,
    string Name,
    bool Enabled,
    int Threshold,
    int WindowSeconds,
    int ObserveSeconds,
    int CooldownSeconds,
    int BanDurationSeconds,
    string Action,
    string? Protocol,
    string? Description,
    int Version,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc);
