namespace IpBan.Shared.Models;

/// <summary>
/// 统一管理 API 返回结构。
/// </summary>
public sealed record ApiResult<T>(bool Success, string Code, string Message, T? Data)
{
    public static ApiResult<T> Ok(T data, string message = "操作成功") =>
        new(true, "OK", message, data);

    public static ApiResult<T> Fail(string code, string message) =>
        new(false, code, message, default);
}

public enum ProtocolKind
{
    Ssh,
    Vnc,
    Rdp,
    OpenSsh,
    WinRm,
    Unidentified = 5
}

public enum EventCompletenessLevel
{
    Full,
    IpEnforceable,
    ObserveOnly
}

public enum FieldAvailability
{
    Available,
    NotProvided,
    NotCollected,
    CorrelationFailed,
    NotApplicable
}

public enum FirewallStatus
{
    Enabled,
    Disabled,
    Unsupported,
    PermissionDenied,
    CommandFailed
}

public enum FirewallActionStatus
{
    Pending,
    Applied,
    Failed,
    Disabled,
    Removed
}

public sealed record LoginEventContract(
    long Id,
    DateTimeOffset OccurredAtUtc,
    ProtocolKind Protocol,
    bool Success,
    string? Username,
    string? RemoteIp,
    int? RemotePort,
    string? LocalIp,
    int? LocalPort,
    int? LocalProcessId,
    string? LocalProcessName,
    int? OriginProcessId,
    string? OriginProcessName,
    EventCompletenessLevel CompletenessLevel,
    FieldAvailability UsernameAvailability,
    FieldAvailability RemoteIpAvailability,
    FieldAvailability EndpointAvailability,
    FieldAvailability ProcessAvailability,
    string Collector,
    string? RawEventId,
    string EvidenceSource);

public sealed record SystemStatusContract(
    string Version,
    string Platform,
    string Runtime,
    bool Ready,
    FirewallStatus FirewallStatus);

/// <summary>
/// 当前登录的本机管理用户。
/// </summary>
public sealed record CurrentUserContract(
    string Name,
    string UserId,
    string Access);

public sealed record LoginResponseContract(
    string Status,
    string Type,
    string CurrentAuthority);

public sealed record ConnectionSnapshotContract(
    string Protocol,
    string State,
    string RemoteIp,
    int? RemotePort,
    string? LocalIp,
    int? LocalPort,
    int? ProcessId,
    string? ProcessName,
    DateTimeOffset ObservedAtUtc);

/// <summary>
/// 当前登录会话与当前 TCP 连接分开建模，便于管理台提供独立页面和断开操作。
/// </summary>
public sealed record LoginSessionContract(
    string Protocol,
    string SessionId,
    string? Username,
    FieldAvailability UsernameAvailability,
    string RemoteIp,
    int? RemotePort,
    string? LocalIp,
    int? LocalPort,
    string? ProcessName,
    FieldAvailability ProcessAvailability,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset? LastObservedAtUtc,
    bool CanDisconnect);
