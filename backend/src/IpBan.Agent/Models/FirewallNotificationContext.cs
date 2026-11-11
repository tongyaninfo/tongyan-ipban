namespace IpBan.Agent.Models;

/// <summary>仅携带调用当时已知的通知事实，不从后续配置反推历史封禁原因。</summary>
public sealed record FirewallNotificationContext(
    string? Reason = null,
    int? DurationSeconds = null,
    long? OriginalActionId = null,
    string? Protocol = null,
    string? TraceId = null);
