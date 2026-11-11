using System.Globalization;
using IpBan.Engine.Services;
using IpBan.Shared.Models;

namespace IpBan.Engine.Tests;

public sealed class LoginEventNormalizerTests
{
    [Fact]
    public void CompleteLanEventIsFull()
    {
        var normalized = LoginEventNormalizer.Normalize(
            1,
            CreateInput(
                username: "alice",
                remoteIp: "198.51.100.20",
                remotePort: 54321,
                localIp: "192.0.2.10",
                localPort: 22,
                localProcessName: "sshd"));

        Assert.Equal(EventCompletenessLevel.Full, normalized.CompletenessLevel);
        Assert.Equal(FieldAvailability.Available, normalized.RemoteIpAvailability);
        Assert.Equal("198.51.100.20", normalized.RemoteIp);
        Assert.Equal("sshd", normalized.LocalProcessName);
    }

    [Fact]
    public void ReliableRemoteIpCanEnforceWhenOtherFieldsAreMissing()
    {
        var normalized = LoginEventNormalizer.Normalize(
            2,
            CreateInput(remoteIp: "203.0.113.10"));

        Assert.Equal(EventCompletenessLevel.IpEnforceable, normalized.CompletenessLevel);
        Assert.Equal(FieldAvailability.Available, normalized.RemoteIpAvailability);
        Assert.Equal("203.0.113.10", normalized.RemoteIp);
        Assert.Null(normalized.RemotePort);
        Assert.Equal(FieldAvailability.NotProvided, normalized.EndpointAvailability);
        Assert.Equal(FieldAvailability.NotProvided, normalized.ProcessAvailability);
    }

    [Fact]
    public void MissingRemoteIpIsObserveOnlyWithoutUnknownPlaceholder()
    {
        var normalized = LoginEventNormalizer.Normalize(
            3,
            CreateInput(username: "alice", localProcessName: "sshd"));

        Assert.Equal(EventCompletenessLevel.ObserveOnly, normalized.CompletenessLevel);
        Assert.Null(normalized.RemoteIp);
        Assert.Equal(FieldAvailability.NotProvided, normalized.RemoteIpAvailability);
        Assert.DoesNotContain("Unknown", normalized.RemoteIp ?? string.Empty);
    }

    [Fact]
    public void LoopbackEventUsesOriginProcessForFullCorrelation()
    {
        var normalized = LoginEventNormalizer.Normalize(
            4,
            CreateInput(
                username: "local-user",
                remoteIp: "127.0.0.1",
                remotePort: 40222,
                localIp: "127.0.0.1",
                localPort: 22,
                localProcessName: "sshd",
                originProcessName: "malicious-client"));

        Assert.Equal(EventCompletenessLevel.Full, normalized.CompletenessLevel);
        Assert.Equal("127.0.0.1", normalized.RemoteIp);
        Assert.Equal("malicious-client", normalized.OriginProcessName);
        Assert.Equal(FieldAvailability.Available, normalized.ProcessAvailability);
    }

    [Fact]
    public void LoopbackWithoutOriginProcessRemainsIpEnforceable()
    {
        var normalized = LoginEventNormalizer.Normalize(
            5,
            CreateInput(
                username: "local-user",
                remoteIp: "::1",
                remotePort: 40222,
                localIp: "::1",
                localPort: 22,
                localProcessName: "sshd"));

        Assert.Equal(EventCompletenessLevel.IpEnforceable, normalized.CompletenessLevel);
        Assert.Equal(FieldAvailability.CorrelationFailed, normalized.ProcessAvailability);
        Assert.Equal("::1", normalized.RemoteIp);
    }

    [Fact]
    public void DeclaredRemoteIpCorrelationFailureCannotBeUsedForBan()
    {
        var normalized = LoginEventNormalizer.Normalize(
            6,
            CreateInput(
                remoteIp: "198.51.100.20",
                remoteIpAvailability: FieldAvailability.CorrelationFailed));

        Assert.Equal(EventCompletenessLevel.ObserveOnly, normalized.CompletenessLevel);
        Assert.Equal(FieldAvailability.CorrelationFailed, normalized.RemoteIpAvailability);
    }

    [Fact]
    public void DeclaredLocalEndpointGapIsPreserved()
    {
        var normalized = LoginEventNormalizer.Normalize(
            7,
            CreateInput(
                remoteIp: "198.51.100.20",
                localEndpointAvailability: FieldAvailability.NotCollected));

        Assert.Equal(EventCompletenessLevel.IpEnforceable, normalized.CompletenessLevel);
        Assert.Equal(FieldAvailability.NotCollected, normalized.EndpointAvailability);
    }

    private static RawLoginEventInput CreateInput(
        string? username = null,
        string? remoteIp = null,
        int? remotePort = null,
        string? localIp = null,
        int? localPort = null,
        string? localProcessName = null,
        string? originProcessName = null,
        FieldAvailability remoteIpAvailability = FieldAvailability.NotProvided,
        FieldAvailability localEndpointAvailability = FieldAvailability.NotProvided) => new(
        OccurredAtUtc: DateTimeOffset.Parse("2026-01-01T00:00:00+00:00", CultureInfo.InvariantCulture),
        Protocol: ProtocolKind.Ssh,
        Success: false,
        Username: username,
        RemoteIp: remoteIp,
        RemotePort: remotePort,
        LocalIp: localIp,
        LocalPort: localPort,
        LocalProcessId: 100,
        LocalProcessName: localProcessName,
        OriginProcessId: 200,
        OriginProcessName: originProcessName,
        Collector: "synthetic",
        RawEventId: "evt-1",
        EvidenceSource: "test",
        RemoteIpAvailability: remoteIpAvailability,
        LocalEndpointAvailability: localEndpointAvailability);
}
