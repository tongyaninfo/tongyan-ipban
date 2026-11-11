namespace IpBan.Shared.Models;

/// <summary>
/// 各平台采集器输出的原始登录事件。采集器可以携带字段可信度，归一化阶段不会用 Unknown 填补缺口。
/// </summary>
public sealed record RawLoginEventInput(
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
    string Collector,
    string? RawEventId,
    string EvidenceSource,
    FieldAvailability RemoteIpAvailability = FieldAvailability.NotProvided,
    FieldAvailability RemotePortAvailability = FieldAvailability.NotProvided,
    FieldAvailability LocalEndpointAvailability = FieldAvailability.NotProvided,
    FieldAvailability UsernameAvailability = FieldAvailability.NotProvided,
    FieldAvailability ProcessAvailability = FieldAvailability.NotProvided);
