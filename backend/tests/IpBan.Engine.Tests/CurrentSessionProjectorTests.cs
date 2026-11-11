using System.Globalization;
using IpBan.Shared.Models;
using IpBan.Shared.Service;

namespace IpBan.Engine.Tests;

public sealed class CurrentSessionProjectorTests
{
    [Fact]
    public void ProjectsActiveSshConnectionAndCorrelatesUsername()
    {
        var observedAt = DateTimeOffset.Parse(
            "2026-11-08T04:31:10Z",
            CultureInfo.InvariantCulture);
        var connection = new ConnectionSnapshotContract(
            "tcp", "ESTAB", "198.51.100.128", 63809, "192.0.2.72", 22, 15336, "sshd", observedAt);
        var loginEvent = new LoginEventContract(
            1,
            observedAt.AddSeconds(-4),
            ProtocolKind.Ssh,
            true,
            "root",
            "198.51.100.128",
            63809,
            null,
            null,
            15336,
            "sshd",
            null,
            null,
            EventCompletenessLevel.IpEnforceable,
            FieldAvailability.Available,
            FieldAvailability.Available,
            FieldAvailability.NotCollected,
            FieldAvailability.Available,
            "linux-sshd-journald",
            "event-1",
            "journald:sshd");

        var session = Assert.Single(CurrentSessionProjector.Project([connection], [loginEvent]));

        Assert.Equal("ssh", session.Protocol);
        Assert.Equal("root", session.Username);
        Assert.Equal(FieldAvailability.Available, session.UsernameAvailability);
        Assert.Equal("198.51.100.128", session.RemoteIp);
        Assert.Equal(63809, session.RemotePort);
        Assert.Equal("sshd", session.ProcessName);
        Assert.True(session.CanDisconnect);
    }

    [Fact]
    public void ExcludesApiConnectionsAndKeepsMissingUsernameExplicit()
    {
        var observedAt = DateTimeOffset.UtcNow;
        var connections = new[]
        {
            new ConnectionSnapshotContract(
                "tcp", "ESTAB", "192.0.2.10", 50000, "192.0.2.20", 5180, 1, "IpBan.Api", observedAt),
            new ConnectionSnapshotContract(
                "tcp", "ESTAB", "192.0.2.10", 50001, "192.0.2.20", 22, 2, "sshd", observedAt)
        };

        var session = Assert.Single(CurrentSessionProjector.Project(connections, []));

        Assert.Null(session.Username);
        Assert.Equal(FieldAvailability.NotCollected, session.UsernameAvailability);
        Assert.Equal(FieldAvailability.Available, session.ProcessAvailability);
    }

    [Fact]
    public void CorrelatesOpenSshEventAndProjectsRdpAsIndependentSession()
    {
        var observedAt = DateTimeOffset.Parse(
            "2026-11-08T10:00:00Z",
            CultureInfo.InvariantCulture);
        var connections = new ConnectionSnapshotContract[]
        {
            new("tcp", "ESTAB", "198.51.100.128", 64367, "192.0.2.73", 22, 1320, "sshd", observedAt),
            new("tcp", "ESTAB", "198.51.100.128", 63822, "192.0.2.73", 3389, 816, "svchost", observedAt)
        };
        var loginEvent = new LoginEventContract(
            2,
            observedAt.AddSeconds(-2),
            ProtocolKind.OpenSsh,
            true,
            "Administrator",
            "198.51.100.128",
            64367,
            null,
            null,
            1320,
            "sshd",
            null,
            null,
            EventCompletenessLevel.IpEnforceable,
            FieldAvailability.Available,
            FieldAvailability.Available,
            FieldAvailability.NotCollected,
            FieldAvailability.Available,
            "windows-eventlog:OpenSSH/Operational",
            "event-2",
            "eventlog:OpenSSH/Operational:4");

        var sessions = CurrentSessionProjector.Project(connections, [loginEvent]);

        Assert.Equal(2, sessions.Count);
        var ssh = Assert.Single(sessions, item => item.Protocol == "ssh");
        Assert.Equal("Administrator", ssh.Username);
        Assert.Equal("ssh:1320:192.0.2.73:22:198.51.100.128:64367", ssh.SessionId);
        var rdp = Assert.Single(sessions, item => item.Protocol == "rdp");
        Assert.Null(rdp.Username);
        Assert.Equal(FieldAvailability.NotCollected, rdp.UsernameAvailability);
        Assert.Equal("192.0.2.73", rdp.LocalIp);
        Assert.Equal(3389, rdp.LocalPort);
    }

    [Fact]
    public void CorrelatesRdpEventWhenEventHasNoRemotePort()
    {
        var observedAt = DateTimeOffset.Parse("2026-11-08T10:00:00Z", CultureInfo.InvariantCulture);
        var connection = new ConnectionSnapshotContract(
            "tcp", "ESTAB", "198.51.100.128", 63822, "192.0.2.73", 3389, 816, "svchost", observedAt);
        var loginEvent = new LoginEventContract(
            3, observedAt.AddSeconds(-1), ProtocolKind.Rdp, true, "Administrator",
            "198.51.100.128", null, null, null, 816, "svchost", null, null,
            EventCompletenessLevel.IpEnforceable, FieldAvailability.Available,
            FieldAvailability.Available, FieldAvailability.NotCollected,
            FieldAvailability.NotCollected, "windows-eventlog:rdp", "event-3", "eventlog:rdp:25");

        var session = Assert.Single(CurrentSessionProjector.Project([connection], [loginEvent]));

        Assert.Equal("Administrator", session.Username);
        Assert.Equal(FieldAvailability.Available, session.UsernameAvailability);
    }

    [Theory]
    [InlineData(22, "sshd", ProtocolKind.Ssh, "ssh")]
    [InlineData(22, "sshd.exe", ProtocolKind.OpenSsh, "ssh")]
    [InlineData(3389, "svchost", ProtocolKind.Rdp, "rdp")]
    [InlineData(5985, "System", ProtocolKind.WinRm, "winrm")]
    [InlineData(5986, "System", ProtocolKind.WinRm, "winrm")]
    [InlineData(5900, "Xvnc", ProtocolKind.Vnc, "vnc")]
    [InlineData(5901, "Xtigervnc", ProtocolKind.Vnc, "vnc")]
    [InlineData(5999, "winvnc", ProtocolKind.Vnc, "vnc")]
    [InlineData(2222, "sshd", ProtocolKind.OpenSsh, "ssh")]
    [InlineData(3390, "termservice", ProtocolKind.Rdp, "rdp")]
    [InlineData(55985, "wsmprovhost", ProtocolKind.WinRm, "winrm")]
    [InlineData(6591, "Xvnc", ProtocolKind.Vnc, "vnc")]
    public void ProjectsSupportedProtocolAndKeepsDisconnectIdentityConsistent(
        int localPort, string processName, ProtocolKind eventProtocol, string expectedProtocol)
    {
        var connection = CreateConnection(localPort, processName);
        var loginEvent = CreateLogin(connection, eventProtocol);

        var session = Assert.Single(CurrentSessionProjector.Project([connection], [loginEvent]));

        Assert.Equal(expectedProtocol, session.Protocol);
        Assert.Equal("test-user", session.Username);
        Assert.Equal(loginEvent.OccurredAtUtc, session.StartedAtUtc);
        Assert.Equal(localPort, session.LocalPort);
        Assert.Equal(connection.RemotePort, session.RemotePort);
        Assert.Equal($"{expectedProtocol}:42:192.0.2.20:{localPort}:192.0.2.10:41000", session.SessionId);
        // API 下线会重新枚举连接并按相同函数匹配完整会话ID，不能只按IP挑选连接。
        Assert.Equal(CurrentSessionProjector.BuildSessionId(connection), session.SessionId);
        Assert.True(session.CanDisconnect);
    }

    [Theory]
    [InlineData("tcp", "LISTEN")]
    [InlineData("tcp", "SYN-SENT")]
    [InlineData("tcp", "CLOSE_WAIT")]
    [InlineData("tcp", "TIME_WAIT")]
    [InlineData("udp", "ESTAB")]
    public void ExcludesNonEstablishedOrNonTcpConnections(string transport, string state)
    {
        var connection = CreateConnection(5985, "System") with { Protocol = transport, State = state };

        Assert.Empty(CurrentSessionProjector.Project([connection], []));
    }

    [Fact]
    public void WinRmAndVncOnSameSourceRemainIndependentDisconnectTargets()
    {
        var winRm = CreateConnection(5985, "System");
        var vnc = CreateConnection(5901, "Xvnc") with { RemotePort = 41001, ProcessId = 43 };
        var anotherWinRm = winRm with { RemotePort = 41002 };
        var connections = new[] { winRm, vnc, anotherWinRm };

        var sessions = CurrentSessionProjector.Project(connections, []);

        Assert.Equal(3, sessions.Count);
        Assert.Equal(3, sessions.Select(item => item.SessionId).Distinct().Count());
        foreach (var session in sessions)
        {
            var target = Assert.Single(connections, item => CurrentSessionProjector.BuildSessionId(item) == session.SessionId);
            Assert.Equal(target.RemotePort, session.RemotePort);
            Assert.Equal(target.LocalPort, session.LocalPort);
        }

        var correctedId = CurrentSessionProjector.BuildSessionId(winRm);
        Assert.StartsWith("winrm:", correctedId);
        Assert.DoesNotContain(sessions, item => item.SessionId == correctedId.Replace("winrm:", "vnc:", StringComparison.Ordinal));
        Assert.NotEqual(correctedId, CurrentSessionProjector.BuildSessionId(winRm with { ProcessId = 44 }));
        Assert.Empty(CurrentSessionProjector.Project([winRm with { State = "CLOSE_WAIT" }], []));
    }

    private static ConnectionSnapshotContract CreateConnection(int localPort, string processName) => new(
        "tcp", "ESTAB", "192.0.2.10", 41000, "192.0.2.20", localPort, 42, processName,
        DateTimeOffset.Parse("2026-11-09T13:00:00Z", CultureInfo.InvariantCulture));

    private static LoginEventContract CreateLogin(ConnectionSnapshotContract connection, ProtocolKind protocol) => new(
        1, connection.ObservedAtUtc.AddSeconds(-2), protocol, true, "test-user",
        connection.RemoteIp, connection.RemotePort, connection.LocalIp, connection.LocalPort,
        connection.ProcessId, connection.ProcessName, null, null, EventCompletenessLevel.Full,
        FieldAvailability.Available, FieldAvailability.Available, FieldAvailability.Available,
        FieldAvailability.Available, "synthetic", "test-event", "synthetic");
}
