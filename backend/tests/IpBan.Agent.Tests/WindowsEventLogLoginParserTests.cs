using System.Xml.Linq;
using IpBan.Agent.Service.impl;
using IpBan.Shared.Models;

namespace IpBan.Agent.Tests;

public sealed class WindowsEventLogLoginParserTests
{
    private static readonly DateTimeOffset OccurredAt = new(2026, 11, 9, 11, 52, 57, TimeSpan.Zero);

    [Fact]
    public void InvalidUserPasswordFailureProducesOneEventAcrossWindowsChannels()
    {
        var records = new[]
        {
            OpenSsh(899, "Invalid user missing-account from 192.0.2.72 port 38042"),
            OpenSsh(900, "Failed password for invalid user missing-account from 192.0.2.72 port 38042 ssh2"),
            OpenSsh(901, "Received disconnect from 192.0.2.72 port 38042:11: Bye Bye [preauth]"),
            OpenSsh(902, "Disconnected from invalid user missing-account 192.0.2.72 port 38042 [preauth]"),
            Security(4625, 23329, "8", @"C:\Windows\System32\OpenSSH\sshd.exe", "NOUSER", "-", "-")
        };

        var result = Assert.Single(records.OfType<RawLoginEventInput>());
        Assert.False(result.Success);
        Assert.Equal(ProtocolKind.OpenSsh, result.Protocol);
        Assert.Equal("missing-account", result.Username);
        Assert.Equal("192.0.2.72", result.RemoteIp);
        Assert.Equal(38042, result.RemotePort);
        Assert.Equal("OpenSSH/Operational:900", result.RawEventId);
        Assert.Equal("sshd", result.LocalProcessName);
        Assert.Equal(8268, result.LocalProcessId);
    }

    [Fact]
    public void MultipleRealAttemptsOnSameConnectionKeepTheirOwnRecordIds()
    {
        var attempts = new[]
        {
            OpenSsh(410, "Failed publickey for user from 192.0.2.72 port 41203 ssh2: ED25519 SHA256:example"),
            OpenSsh(411, "Failed password for user from 192.0.2.72 port 41203 ssh2"),
            OpenSsh(412, "Accepted password for user from 192.0.2.72 port 41203 ssh2")
        }.OfType<RawLoginEventInput>().ToArray();

        Assert.Equal(3, attempts.Length);
        Assert.Equal(2, attempts.Count(attempt => !attempt.Success));
        Assert.Equal(3, attempts.Select(attempt => attempt.RawEventId).Distinct().Count());
        Assert.All(attempts, attempt => Assert.Equal(41203, attempt.RemotePort));
    }

    [Theory]
    [InlineData("Failed none for invalid user user from 192.0.2.72 port 41203 ssh2")]
    [InlineData("Postponed publickey for user from 192.0.2.72 port 41203 ssh2")]
    [InlineData("Partial publickey for user from 192.0.2.72 port 41203 ssh2")]
    [InlineData("Connection closed by invalid user user 192.0.2.72 port 41203 [preauth]")]
    public void NegotiationAndAuxiliaryLinesAreNotAuthenticationResults(string payload) =>
        Assert.Null(OpenSsh(410, payload));

    [Fact]
    public void AcceptedNoneIsAnAuthenticationSuccess()
    {
        var result = OpenSsh(412, "Accepted none for user from 192.0.2.72 port 41203 ssh2");

        Assert.NotNull(result);
        Assert.True(result.Success);
    }

    [Fact]
    public void FormattedMessageFallbackSupportsWindowsAccountNamesAndIpv6()
    {
        var parsed = WindowsEventLogParser.TryParse("OpenSSH/Operational", 4, 412, OccurredAt, null,
            @"sshd: Accepted password for EXAMPLE\Example User from 2001:db8::2 port 41000 ssh2", out var result);

        Assert.True(parsed);
        Assert.True(result.Success);
        Assert.Equal(@"EXAMPLE\Example User", result.Username);
        Assert.Equal("2001:db8::2", result.RemoteIp);
        Assert.Equal(41000, result.RemotePort);
    }

    [Fact]
    public void EndpointTextInsideInvalidUsernameCannotPickAnotherIp()
    {
        var unambiguous = OpenSsh(410,
            "Failed password for invalid user name from 192.0.2.99 port 81 from 192.0.2.72 port 41203 ssh2");
        Assert.NotNull(unambiguous);
        Assert.Equal("192.0.2.72", unambiguous.RemoteIp);
        Assert.Equal(41203, unambiguous.RemotePort);

        var ambiguous = OpenSsh(411,
            "Failed password for invalid user name from 192.0.2.99 port 81 ssh2: detail from 192.0.2.72 port 41203 ssh2");
        Assert.NotNull(ambiguous);
        Assert.False(ambiguous.Success);
        Assert.Null(ambiguous.RemoteIp);
        Assert.Null(ambiguous.RemotePort);
        Assert.Equal(FieldAvailability.CorrelationFailed, ambiguous.RemoteIpAvailability);
    }

    [Theory]
    [InlineData(@"C:\Windows\System32\OpenSSH\sshd.exe")]
    [InlineData(@"C:\Windows\System32\OpenSSH\SSHD-SESSION.EXE")]
    [InlineData(@"C:\Windows\System32\OpenSSH\sshd-auth.exe")]
    public void SecurityEventsFromOpenSshExecutablesAreOnlySupportingEvidence(string processName)
    {
        Assert.Null(Security(4625, 800, "8", processName, "user", "192.0.2.72", "41203"));
        Assert.Null(Security(4624, 801, "8", processName, "user", "192.0.2.72", "41203"));
    }

    [Theory]
    [InlineData(4624, "10", @"C:\Windows\System32\svchost.exe", ProtocolKind.Rdp)]
    [InlineData(4625, "10", @"C:\Windows\System32\svchost.exe", ProtocolKind.Rdp)]
    [InlineData(4625, "3", @"C:\Windows\System32\wsmprovhost.exe", ProtocolKind.WinRm)]
    [InlineData(4625, "3", "-", ProtocolKind.Unidentified)]
    public void SecurityAuthenticationUsesStructuredEvidence(int id, string logonType, string processName, ProtocolKind protocol)
    {
        var result = Security(id, 412, logonType, processName, "NOUSER", "192.0.2.72", "41203");

        Assert.NotNull(result);
        Assert.Equal(id == 4624, result.Success);
        Assert.Equal(protocol, result.Protocol);
        Assert.Equal("NOUSER", result.Username);
        Assert.Equal("192.0.2.72", result.RemoteIp);
        Assert.Equal(41203, result.RemotePort);
    }

    [Fact]
    public void SecurityServiceLogonCanSucceedWithoutAnIdentifiableProtocolOrAddress()
    {
        var result = Security(4624, 412, "5", @"C:\Windows\System32\services.exe", "SYSTEM", "-", "-");

        Assert.NotNull(result);
        Assert.True(result.Success);
        Assert.Equal(ProtocolKind.Unidentified, result.Protocol);
        Assert.Null(result.RemoteIp);
        Assert.Equal(FieldAvailability.NotProvided, result.RemoteIpAvailability);
    }

    [Theory]
    [InlineData("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 21, "Session logon succeeded")]
    [InlineData("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 22, "Shell start succeeded")]
    [InlineData("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 25, "Session reconnection succeeded")]
    [InlineData("Microsoft-Windows-WinRM/Operational", 132, "WSMan operation Identify failed")]
    [InlineData("Microsoft-Windows-WinRM/Operational", 145, "Logon error")]
    public void ServiceLifecycleAndOperationMessagesDoNotCreateLoginRecords(string channel, int id, string message) =>
        Assert.False(WindowsEventLogParser.TryParse(channel, id, 412, OccurredAt, null, message, out _));

    private static RawLoginEventInput? OpenSsh(long recordId, string payload)
    {
        var xml = EventXml(("process", "sshd"), ("payload", payload));
        return WindowsEventLogParser.TryParse("OpenSSH/Operational", 4, recordId, OccurredAt, xml,
            "本地化格式说明", out var result) ? result : null;
    }

    private static RawLoginEventInput? Security(int id, long recordId, string logonType, string processName,
        string username, string ip, string port)
    {
        var xml = EventXml(("TargetUserName", username), ("LogonType", logonType), ("ProcessName", processName),
            ("IpAddress", ip), ("IpPort", port));
        return WindowsEventLogParser.TryParse("Security", id, recordId, OccurredAt, xml, null, out var result) ? result : null;
    }

    private static string EventXml(params (string Name, string Value)[] data)
    {
        XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
        return new XElement(ns + "Event",
            new XElement(ns + "System", new XElement(ns + "Execution", new XAttribute("ProcessID", 8268))),
            new XElement(ns + "EventData", data.Select(item => new XElement(ns + "Data",
                new XAttribute("Name", item.Name), item.Value)))).ToString();
    }
}
