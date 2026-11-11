using IpBan.Shared.Models;

namespace IpBan.Engine.Models;

public enum DecisionAction
{
    Allow,
    Observe,
    Ban
}

public sealed record BanPolicySnapshot(
    long Version,
    int FailureThreshold,
    TimeSpan Window,
    TimeSpan BanDuration,
    bool Enabled);

public sealed record DecisionInput(
    string SourceIp,
    ProtocolKind Protocol,
    int FailureCountInWindow,
    bool IsWhitelisted,
    bool IsBlacklisted,
    BanPolicySnapshot Policy,
    DateTimeOffset EvaluatedAtUtc);

public sealed record BanDecision(
    DecisionAction Action,
    string SourceIp,
    ProtocolKind Protocol,
    long PolicyVersion,
    int FailureCountInWindow,
    DateTimeOffset EvaluatedAtUtc,
    DateTimeOffset? ExpiresAtUtc,
    string Reason);
