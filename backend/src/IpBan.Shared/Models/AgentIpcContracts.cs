using IpBan.Shared.Logging.Syslog;

namespace IpBan.Shared.Models;

/// <summary>
/// Agent 与本机管理 API 之间的 Unix Domain Socket 操作名。
/// </summary>
public static class AgentIpcOperations
{
    public const string ListConnections = "list_connections";
    public const string ListLoginEvents = "list_login_events";
    public const string Ban = "ban";
    public const string Unban = "unban";
    public const string Disconnect = "disconnect";
    public const string DisconnectExact = "disconnect_exact";
    public const string ProbeFirewall = "probe_firewall";
    public const string SyslogStatus = "syslog_status";
}

/// <summary>
/// 管理 API 发给 Agent 的单行 JSON 请求。
/// </summary>
public sealed record AgentIpcRequest(
    string Operation,
    string? SourceAddress = null,
    int? DurationSeconds = null,
    bool DisconnectExisting = false,
    int? Limit = null,
    ConnectionSnapshotContract? Connection = null,
    long? ActionId = null,
    string? TraceId = null);

/// <summary>
/// 已有 TCP 连接的断开尝试结果。断开连接是独立于防火墙写入的动作。
/// </summary>
public sealed record ConnectionTerminationContract(
    bool Success,
    int Attempted,
    int Terminated,
    string? Error);

/// <summary>
/// 人工封禁的组合结果，明确区分防火墙动作和已有连接处置。
/// </summary>
public sealed record ManualBanResult(
    FirewallActionResult FirewallAction,
    ConnectionTerminationContract ExistingConnectionTermination,
    int DurationSeconds);

/// <summary>
/// Agent IPC 的响应。Connections 在非查询操作中为空数组，避免 AOT 下的可选集合歧义。
/// </summary>
public sealed record AgentIpcResponse(
    bool Success,
    string Code,
    string Message,
    ConnectionSnapshotContract[] Connections,
    LoginEventContract[] LoginEvents,
    ManualBanResult? BanResult,
    ConnectionTerminationContract? DisconnectionResult,
    FirewallObservation? FirewallObservation = null,
    FirewallActionResult? UnbanResult = null,
    SyslogProcessStatus? SyslogStatus = null);
