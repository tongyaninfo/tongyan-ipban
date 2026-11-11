using System.Globalization;
using IpBan.Shared.Models;

namespace IpBan.Shared.Service;

/// <summary>
/// 将当前 TCP 连接和最近成功登录事件关联为当前登录会话。
/// 连接是实时事实，登录事件用于补齐用户名；关联失败时保留连接并标记字段未采集。
/// </summary>
public static class CurrentSessionProjector
{
    public static IReadOnlyList<LoginSessionContract> Project(
        IReadOnlyList<ConnectionSnapshotContract> connections,
        IReadOnlyList<LoginEventContract> loginEvents)
    {
        ArgumentNullException.ThrowIfNull(connections);
        ArgumentNullException.ThrowIfNull(loginEvents);

        var sessions = new List<LoginSessionContract>();
        foreach (var connection in connections)
        {
            var protocol = ResolveSessionProtocol(connection);
            if (protocol is null)
            {
                continue;
            }

            var matchedEvent = FindSuccessfulLogin(connection, protocol, loginEvents);
            var processAvailability = string.IsNullOrWhiteSpace(connection.ProcessName)
                ? FieldAvailability.NotCollected
                : FieldAvailability.Available;
            var username = matchedEvent?.Username;
            var usernameAvailability = matchedEvent is not null
                && matchedEvent.UsernameAvailability == FieldAvailability.Available
                && !string.IsNullOrWhiteSpace(username)
                    ? FieldAvailability.Available
                    : FieldAvailability.NotCollected;
            var sessionId = BuildSessionId(connection);

            sessions.Add(new LoginSessionContract(
                Protocol: protocol,
                SessionId: sessionId,
                Username: usernameAvailability == FieldAvailability.Available ? username : null,
                UsernameAvailability: usernameAvailability,
                RemoteIp: connection.RemoteIp,
                RemotePort: connection.RemotePort,
                LocalIp: connection.LocalIp,
                LocalPort: connection.LocalPort,
                ProcessName: connection.ProcessName,
                ProcessAvailability: processAvailability,
                StartedAtUtc: matchedEvent?.OccurredAtUtc ?? connection.ObservedAtUtc,
                LastObservedAtUtc: connection.ObservedAtUtc,
                CanDisconnect: true));
        }

        return sessions
            .OrderByDescending(session => session.LastObservedAtUtc ?? session.StartedAtUtc)
            .ToArray();
    }

    private static string? ResolveSessionProtocol(ConnectionSnapshotContract connection)
    {
        if (!connection.Protocol.Equals("tcp", StringComparison.OrdinalIgnoreCase)
            || !connection.State.Equals("ESTAB", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (connection.LocalPort == 22
            || connection.ProcessName?.Contains("ssh", StringComparison.OrdinalIgnoreCase) == true)
        {
            return "ssh";
        }

        if (connection.LocalPort == 3389
            || connection.ProcessName?.Contains("termservice", StringComparison.OrdinalIgnoreCase) == true)
        {
            return "rdp";
        }

        // WinRM 的明确端口也处于 VNC 的宽泛端口范围内，必须优先识别，
        // 否则会话协议、用户名关联和用于下线的会话ID都会被错误标记为VNC。
        if (connection.LocalPort is 5985 or 5986
            || connection.ProcessName?.Contains("winrm", StringComparison.OrdinalIgnoreCase) == true
            || connection.ProcessName?.Contains("wsmprovhost", StringComparison.OrdinalIgnoreCase) == true)
        {
            return "winrm";
        }

        if (connection.LocalPort is >= 5900 and <= 5999
            || connection.ProcessName?.Contains("vnc", StringComparison.OrdinalIgnoreCase) == true)
        {
            return "vnc";
        }

        return null;
    }

    private static LoginEventContract? FindSuccessfulLogin(
        ConnectionSnapshotContract connection,
        string sessionProtocol,
        IReadOnlyList<LoginEventContract> loginEvents)
    {
        var candidates = loginEvents
            .Where(loginEvent =>
                loginEvent.Success
                && IsMatchingProtocol(loginEvent.Protocol, sessionProtocol)
                && string.Equals(loginEvent.RemoteIp, connection.RemoteIp, StringComparison.OrdinalIgnoreCase)
                // RDP/WinRM 事件经常没有远端端口；只要远端 IP 和协议匹配仍可关联用户名。
                && (loginEvent.RemotePort is null || loginEvent.RemotePort == connection.RemotePort)
                && loginEvent.OccurredAtUtc <= connection.ObservedAtUtc.Add(TimeSpan.FromMinutes(1))
                && loginEvent.OccurredAtUtc >= connection.ObservedAtUtc.Subtract(TimeSpan.FromDays(1)))
            .OrderByDescending(loginEvent => loginEvent.LocalProcessId == connection.ProcessId)
            .ThenByDescending(loginEvent => loginEvent.OccurredAtUtc);

        return candidates.FirstOrDefault();
    }

    private static bool IsMatchingProtocol(ProtocolKind protocol, string sessionProtocol) =>
        sessionProtocol switch
        {
            "ssh" => protocol is ProtocolKind.Ssh or ProtocolKind.OpenSsh,
            "rdp" => protocol == ProtocolKind.Rdp,
            "vnc" => protocol == ProtocolKind.Vnc,
            "winrm" => protocol == ProtocolKind.WinRm,
            _ => false
        };

    public static string BuildSessionId(ConnectionSnapshotContract connection) =>
        $"{ResolveSessionProtocol(connection) ?? "tcp"}:{connection.ProcessId?.ToString(CultureInfo.InvariantCulture) ?? "none"}:{connection.LocalIp ?? "none"}:{connection.LocalPort?.ToString(CultureInfo.InvariantCulture) ?? "none"}:{connection.RemoteIp}:{connection.RemotePort?.ToString(CultureInfo.InvariantCulture) ?? "none"}";
}
