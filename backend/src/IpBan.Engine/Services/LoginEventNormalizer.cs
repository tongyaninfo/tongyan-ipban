using System.Net;
using IpBan.Shared.Models;

namespace IpBan.Engine.Services;

/// <summary>
/// 把 Windows/Linux 采集器的原始事件归一化为可持久化合同。
/// 这里不访问系统 API，也不把缺失字段伪造成 Unknown。
/// </summary>
public static class LoginEventNormalizer
{
    public static LoginEventContract Normalize(long id, RawLoginEventInput input)
    {
        ArgumentNullException.ThrowIfNull(input);

        var remoteIp = NormalizeIp(input.RemoteIp);
        var remoteIpAvailability = ResolveIpAvailability(
            remoteIp,
            input.RemoteIp,
            input.RemoteIpAvailability);

        var remotePortAvailability = ResolvePortAvailability(
            input.RemotePort,
            input.RemotePortAvailability);

        var localIp = NormalizeIp(input.LocalIp);
        var localIpAvailability = ResolveIpAvailability(
            localIp,
            input.LocalIp,
            FieldAvailability.NotProvided);

        var localPortAvailability = ResolvePortAvailability(
            input.LocalPort,
            FieldAvailability.NotProvided);

        var username = NormalizeText(input.Username);
        var usernameAvailability = ResolveTextAvailability(
            username,
            input.UsernameAvailability);

        var isLoopback = remoteIp is not null && IPAddress.TryParse(remoteIp, out var parsedRemoteIp)
            && IPAddress.IsLoopback(parsedRemoteIp);
        var processAvailability = ResolveProcessAvailability(input, isLoopback);

        var derivedLocalEndpointAvailability = Combine(
            localIpAvailability,
            localPortAvailability);
        var localEndpointAvailability = ResolveAggregateAvailability(
            derivedLocalEndpointAvailability,
            input.LocalEndpointAvailability);
        var endpointAvailability = Combine(
            remotePortAvailability,
            localEndpointAvailability);

        var completenessLevel = DetermineCompleteness(
            remoteIpAvailability,
            usernameAvailability,
            remotePortAvailability,
            localEndpointAvailability,
            processAvailability);

        return new LoginEventContract(
            Id: id,
            OccurredAtUtc: input.OccurredAtUtc.ToUniversalTime(),
            Protocol: input.Protocol,
            Success: input.Success,
            Username: username,
            RemoteIp: remoteIp,
            RemotePort: IsAvailable(remotePortAvailability) ? input.RemotePort : null,
            LocalIp: localIp,
            LocalPort: IsAvailable(localPortAvailability) ? input.LocalPort : null,
            LocalProcessId: input.LocalProcessId,
            LocalProcessName: NormalizeText(input.LocalProcessName),
            OriginProcessId: input.OriginProcessId,
            OriginProcessName: NormalizeText(input.OriginProcessName),
            CompletenessLevel: completenessLevel,
            UsernameAvailability: usernameAvailability,
            RemoteIpAvailability: remoteIpAvailability,
            EndpointAvailability: endpointAvailability,
            ProcessAvailability: processAvailability,
            Collector: NormalizeText(input.Collector) ?? string.Empty,
            RawEventId: NormalizeText(input.RawEventId),
            EvidenceSource: NormalizeText(input.EvidenceSource) ?? string.Empty);
    }

    private static EventCompletenessLevel DetermineCompleteness(
        FieldAvailability remoteIpAvailability,
        FieldAvailability usernameAvailability,
        FieldAvailability remotePortAvailability,
        FieldAvailability localEndpointAvailability,
        FieldAvailability processAvailability)
    {
        // 没有可靠远端 IP 时只能观察，不能参与 IP 级别封禁。
        if (!IsAvailable(remoteIpAvailability))
        {
            return EventCompletenessLevel.ObserveOnly;
        }

        return IsAvailable(usernameAvailability)
            && IsAvailable(remotePortAvailability)
            && IsAvailable(localEndpointAvailability)
            && IsAvailable(processAvailability)
            ? EventCompletenessLevel.Full
            : EventCompletenessLevel.IpEnforceable;
    }

    private static FieldAvailability ResolveProcessAvailability(
        RawLoginEventInput input,
        bool isLoopback)
    {
        var declared = input.ProcessAvailability;
        if (declared is FieldAvailability.NotCollected
            or FieldAvailability.CorrelationFailed
            or FieldAvailability.NotApplicable)
        {
            return declared;
        }

        var localProcessName = NormalizeText(input.LocalProcessName);
        var originProcessName = NormalizeText(input.OriginProcessName);

        if (isLoopback)
        {
            // 回环连接的重点是本机发起方；只有服务进程名不能证明是谁发起了连接。
            if (originProcessName is not null)
            {
                return FieldAvailability.Available;
            }

            return declared == FieldAvailability.Available
                ? FieldAvailability.CorrelationFailed
                : FieldAvailability.CorrelationFailed;
        }

        return localProcessName is not null
            ? FieldAvailability.Available
            : declared == FieldAvailability.Available
                ? FieldAvailability.CorrelationFailed
                : FieldAvailability.NotProvided;
    }

    private static FieldAvailability ResolveIpAvailability(
        string? normalized,
        string? original,
        FieldAvailability declared)
    {
        if (declared is FieldAvailability.NotCollected
            or FieldAvailability.CorrelationFailed
            or FieldAvailability.NotApplicable)
        {
            return declared;
        }

        if (normalized is not null)
        {
            return FieldAvailability.Available;
        }

        return string.IsNullOrWhiteSpace(original)
            ? FieldAvailability.NotProvided
            : FieldAvailability.CorrelationFailed;
    }

    private static FieldAvailability ResolvePortAvailability(
        int? port,
        FieldAvailability declared)
    {
        if (declared is FieldAvailability.NotCollected
            or FieldAvailability.CorrelationFailed
            or FieldAvailability.NotApplicable)
        {
            return declared;
        }

        if (port is >= 1 and <= 65535)
        {
            return FieldAvailability.Available;
        }

        return port is null
            ? FieldAvailability.NotProvided
            : FieldAvailability.CorrelationFailed;
    }

    private static FieldAvailability ResolveTextAvailability(
        string? value,
        FieldAvailability declared)
    {
        if (declared is FieldAvailability.NotCollected
            or FieldAvailability.CorrelationFailed
            or FieldAvailability.NotApplicable)
        {
            return declared;
        }

        if (value is not null)
        {
            return FieldAvailability.Available;
        }

        return declared == FieldAvailability.Available
            ? FieldAvailability.CorrelationFailed
            : FieldAvailability.NotProvided;
    }

    private static FieldAvailability Combine(
        FieldAvailability first,
        FieldAvailability second)
    {
        if (first == FieldAvailability.CorrelationFailed
            || second == FieldAvailability.CorrelationFailed)
        {
            return FieldAvailability.CorrelationFailed;
        }

        if (first == FieldAvailability.NotCollected
            || second == FieldAvailability.NotCollected)
        {
            return FieldAvailability.NotCollected;
        }

        if (first == FieldAvailability.NotProvided
            || second == FieldAvailability.NotProvided)
        {
            return FieldAvailability.NotProvided;
        }

        if (first == FieldAvailability.NotApplicable
            || second == FieldAvailability.NotApplicable)
        {
            return FieldAvailability.NotApplicable;
        }

        return FieldAvailability.Available;
    }

    private static FieldAvailability ResolveAggregateAvailability(
        FieldAvailability derived,
        FieldAvailability declared)
    {
        if (declared is FieldAvailability.NotCollected
            or FieldAvailability.CorrelationFailed
            or FieldAvailability.NotApplicable)
        {
            return declared;
        }

        if (declared == FieldAvailability.Available)
        {
            return derived == FieldAvailability.Available
                ? FieldAvailability.Available
                : FieldAvailability.CorrelationFailed;
        }

        return derived;
    }

    private static bool IsAvailable(FieldAvailability availability) =>
        availability == FieldAvailability.Available;

    private static string? NormalizeIp(string? value)
    {
        var text = NormalizeText(value);
        return text is not null && IPAddress.TryParse(text, out var address)
            ? address.ToString()
            : null;
    }

    private static string? NormalizeText(string? value)
    {
        var text = value?.Trim();
        return string.IsNullOrWhiteSpace(text) ? null : text;
    }
}
