namespace IpBan.Shared.Models;

/// <summary>
/// Provider 的能力声明。已有连接断开不由防火墙 Provider 隐式完成。
/// </summary>
public sealed record FirewallCapabilities(
    string Provider,
    string Platform,
    bool SupportsBan,
    bool SupportsUnban,
    bool SupportsCidr,
    bool SupportsExistingConnectionTermination,
    bool RequiresElevatedPrivileges);

/// <summary>
/// 一次 Provider 探测结果。
/// </summary>
public sealed record FirewallObservation(
    string Provider,
    FirewallStatus Status,
    bool IsActive,
    string? Detail,
    DateTimeOffset ObservedAtUtc,
    FirewallCapabilities Capabilities)
{
    public bool ProtectionDegraded => Status != FirewallStatus.Enabled;
}

/// <summary>
/// Ban/Unban 的最终结果。Disabled/Failed 不代表已经写入宿主防火墙。
/// </summary>
public sealed record FirewallActionResult(
    string Provider,
    string SourceAddress,
    FirewallActionStatus ActionStatus,
    FirewallStatus FirewallStatus,
    string? ErrorCode,
    string? ErrorMessage,
    DateTimeOffset CompletedAtUtc)
{
    public bool ProtectionDegraded => FirewallStatus != FirewallStatus.Enabled
        || ActionStatus is FirewallActionStatus.Disabled or FirewallActionStatus.Failed;
}
