using System.Globalization;
using System.Text.Json;
using IpBan.Agent.Options;
using IpBan.Agent.Service.impl;
using IpBan.Engine.Services;
using IpBan.Shared.Models;
using Microsoft.Extensions.Logging.Abstractions;

namespace IpBan.Agent.Tests;

public sealed class LinuxVncLoginCollectorTests
{
    private const string DateHeader = "Mon Nov  9 20:07:28 2026";

    [Fact]
    public void OneFailedAuthenticationProducesOneIpEnforceableEvent()
    {
        var parser = CreateParser();
        Assert.Null(parser.Parse("Connections: accepted: 192.0.2.73::51038", "fixture", "accepted"));
        var raw = parser.Parse("VNCSConnST: closing 192.0.2.73::51038: Authentication failure", "fixture", "failure");
        Assert.NotNull(raw);
        Assert.False(raw.Success);
        Assert.Equal("192.0.2.73", raw.RemoteIp);
        Assert.Equal(51038, raw.RemotePort);
        Assert.Equal("192.0.2.72", raw.LocalIp);
        Assert.Equal(5901, raw.LocalPort);
        Assert.Null(raw.Username);
        Assert.Equal(FieldAvailability.NotProvided, raw.UsernameAvailability);
        Assert.Equal(EventCompletenessLevel.IpEnforceable, LoginEventNormalizer.Normalize(1, raw).CompletenessLevel);
        Assert.Null(parser.Parse("Connections: closed: 192.0.2.73::51038", "fixture", "closed"));
        Assert.Null(parser.Parse("VNCServerST: stopping desktop", "fixture", "stopping"));
    }

    [Fact]
    public void EveryAuthenticationSuccessIsRecordedWithoutDesktopRestart()
    {
        var parser = CreateParser();
        for (var port = 51037; port < 51040; port++)
        {
            Assert.Null(parser.Parse($"Connections: accepted: 192.0.2.73::{port}", "fixture", $"accepted-{port}"));
            Assert.Null(parser.Parse("VNCServerST: starting desktop", "fixture", "desktop"));
            var success = parser.Parse("VNCSConnST: Server default pixel format depth 24 (32bpp)", "fixture", $"success-{port}");
            Assert.NotNull(success);
            Assert.True(success.Success);
            Assert.Equal(port, success.RemotePort);
            Assert.Null(parser.Parse("SConnection: reading client initialisation", "fixture", "init"));
        }
    }

    [Fact]
    public void InterleavedHandshakeDoesNotAttributeAnonymousSuccessToWrongIp()
    {
        var parser = CreateParser();
        parser.Parse("Connections: accepted: 192.0.2.10::51001", "fixture", "a");
        parser.Parse("Connections: accepted: 192.0.2.11::51002", "fixture", "b");
        var success = parser.Parse("VNCSConnST: Server default pixel format depth 24", "fixture", "success");
        Assert.NotNull(success);
        Assert.Null(success.RemoteIp);
        Assert.Equal(EventCompletenessLevel.ObserveOnly, LoginEventNormalizer.Normalize(1, success).CompletenessLevel);
        var failure = parser.Parse("VNCSConnST: closing 192.0.2.10::51001: Authentication failure", "fixture", "failure");
        Assert.Equal("192.0.2.10", failure!.RemoteIp);
        var stillAmbiguous = parser.Parse("VNCSConnST: Server default pixel format depth 24", "fixture", "success2");
        Assert.Null(stillAmbiguous!.RemoteIp);
    }

    [Fact]
    public void ExcessPendingConnectionsCannotTurnAmbiguousSuccessIntoKnownSource()
    {
        var parser = CreateParser();
        for (var port = 10000; port <= 11024; port++)
        {
            parser.Parse($"Connections: accepted: 192.0.2.73::{port}", "fixture", $"accepted-{port}");
        }
        var success = parser.Parse("VNCSConnST: Server default pixel format depth 24", "fixture", "success");
        Assert.NotNull(success);
        Assert.Null(success.RemoteIp);
        for (var port = 10000; port < 11024; port++)
        {
            parser.Parse($"VNCSConnST: closing 192.0.2.73::{port}: Clean disconnection", "fixture", $"closed-{port}");
        }
        parser.Parse("Connections: accepted: 192.0.2.74::12000", "fixture", "new-accepted");
        var afterKnownConnectionsClosed = parser.Parse("VNCSConnST: Server default pixel format depth 24", "fixture", "later-success");
        Assert.Null(afterKnownConnectionsClosed!.RemoteIp);
        var failure = parser.Parse("VNCSConnST: closing 192.0.2.73::11024: Authentication failure", "fixture", "failure");
        Assert.Equal("192.0.2.73", failure!.RemoteIp);
        Assert.Equal(11024, failure.RemotePort);
    }

    [Theory]
    [InlineData("2001:db8::73::51038", "2001:db8::73")]
    [InlineData("[fe80::1234%5]::51038", "fe80::1234%5")]
    [InlineData("::1::51038", "::1")]
    [InlineData("::ffff:192.0.2.73::51038", "192.0.2.73")]
    public void PreservesIpv6AndLoopbackAddress(string endpoint, string expected)
    {
        var raw = CreateParser().Parse($"VNCSConnST: closing {endpoint}: Authentication failure", "fixture", "failure");
        Assert.Equal(expected, raw!.RemoteIp);
        Assert.Equal(51038, raw.RemotePort);
    }

    [Theory]
    [InlineData("VNCSConnST: closing 192.0.2.73::51038: Clean disconnection")]
    [InlineData("VNCSConnST: closing 192.0.2.73::51038: read: Connection reset by peer")]
    [InlineData("Connections: accepted: 192.0.2.73::51038")]
    [InlineData("SConnection: Client requests security type VncAuth(2)")]
    public void TcpAndNegotiationMessagesAreNotAuthentication(string line)
    {
        Assert.Null(CreateParser().Parse(line, "fixture", "probe"));
    }

    [Fact]
    public void JournalReplayAndIndependentProcessesKeepTheirOwnContexts()
    {
        var collector = NewCollector(new LinuxVncCollectorOptions());
        var output = string.Join('\n',
            Journal("listen100", "100", "vncext: Listening for VNC connections on 192.0.2.72 interface(s),"),
            Journal("listen101", "101", "vncext: Listening for VNC connections on 192.0.2.72 interface(s),"),
            Journal("a", "100", "Connections: accepted: 192.0.2.10::51001"),
            Journal("b", "101", "Connections: accepted: 192.0.2.11::51002"),
            Journal("c", "100", "VNCSConnST: Server default pixel format depth 24"),
            Journal("d", "101", "VNCSConnST: closing 192.0.2.11::51002: Authentication failure"));
        var events = collector.ParseJournalOutput(output);
        Assert.Equal(2, events.Count);
        Assert.Equal("192.0.2.10", events[0].RemoteIp);
        Assert.Equal(100, events[0].LocalProcessId);
        Assert.Equal("192.0.2.11", events[1].RemoteIp);
        Assert.Empty(collector.ParseJournalOutput(output));
    }

    [Fact]
    public void PartialJournalContextCannotAttributeAnonymousSuccessToKnownSource()
    {
        var collector = NewCollector(new LinuxVncCollectorOptions());
        var events = collector.ParseJournalOutput(string.Join('\n',
            Journal("accepted", "100", "Connections: accepted: 192.0.2.10::51001"),
            Journal("success", "100", "VNCSConnST: Server default pixel format depth 24")));
        var success = Assert.Single(events);
        Assert.True(success.Success);
        Assert.Null(success.RemoteIp);
        Assert.Equal(EventCompletenessLevel.ObserveOnly, LoginEventNormalizer.Normalize(1, success).CompletenessLevel);
    }

    [Fact]
    public async Task FileWaitsForNewlineAndReplaysResultForPersistenceRetry()
    {
        var path = NewLogPath();
        var timestamp = DateTimeOffset.Now;
        await File.WriteAllTextAsync(path, NativeDate(timestamp) + "\nConnections: accepted: 192.0.2.73::51038\n");
        var collector = NewCollector(new LinuxVncCollectorOptions { Source = "Files", LogFiles = [path] });
        Assert.Empty(await collector.ReadAsync(timestamp));
        await File.AppendAllTextAsync(path, "VNCSConnST: closing 192.0.2.73::51038: Authentication failure");
        Assert.Empty(await collector.ReadAsync(timestamp));
        await File.AppendAllTextAsync(path, "\n");
        var first = Assert.Single(await collector.ReadAsync(timestamp));
        var retry = Assert.Single(await collector.ReadAsync(timestamp.AddSeconds(2)));
        Assert.Equal(first.RawEventId, retry.RawEventId);
        Assert.Equal(first.OccurredAtUtc, retry.OccurredAtUtc);
        Assert.False(first.Success);
    }

    [Fact]
    public async Task FileTruncationAndReplacementDoNotLoseSubsequentFailures()
    {
        var path = NewLogPath();
        var now = DateTimeOffset.Now;
        var header = NativeDate(now);
        await File.WriteAllTextAsync(path, $"{header}\nVNCSConnST: closing 192.0.2.73::51038: Authentication failure\n");
        var collector = NewCollector(new LinuxVncCollectorOptions { Source = "Files", LogFiles = [path] });
        Assert.Single(await collector.ReadAsync(now));
        // 原地替换且长度相同，单看文件长度不能识别这类日志轮转。
        await File.WriteAllTextAsync(path, $"{header}\nVNCSConnST: closing 192.0.2.73::51039: Authentication failure\n");
        Assert.Equal(2, (await collector.ReadAsync(now)).Count);
        await File.WriteAllTextAsync(path, "");
        await collector.ReadAsync(now);
        await File.AppendAllTextAsync(path, $"{header}\nVNCSConnST: closing 192.0.2.73::51040: Authentication failure\n");
        Assert.Equal(3, (await collector.ReadAsync(now)).Count);
    }

    [Fact]
    public async Task FiveRealFailuresRemainFiveAfterRepeatedPollsAndCanReachThreshold()
    {
        var path = NewLogPath();
        var now = DateTimeOffset.Now;
        var lines = Enumerable.Range(51038, 5).SelectMany(port => new[]
        {
            $"Connections: accepted: 192.0.2.73::{port}",
            $"VNCSConnST: closing 192.0.2.73::{port}: Authentication failure",
            $"Connections: closed: 192.0.2.73::{port}"
        });
        await File.WriteAllTextAsync(path, NativeDate(now) + "\n" + string.Join('\n', lines) + "\n");
        var collector = NewCollector(new LinuxVncCollectorOptions { Source = "Files", LogFiles = [path] });
        var events = await collector.ReadAsync(now);
        Assert.Equal(5, events.Count);
        Assert.Equal(5, events.Select(item => item.RawEventId).Distinct().Count());
        Assert.All(events, item => Assert.Equal(EventCompletenessLevel.IpEnforceable, LoginEventNormalizer.Normalize(1, item).CompletenessLevel));
        Assert.Equal(events.Select(item => item.RawEventId), (await collector.ReadAsync(now.AddSeconds(2))).Select(item => item.RawEventId));
    }

    [Fact]
    public async Task FileWithoutNativeTimestampCannotInventCurrentTimeForOldEvidence()
    {
        var path = NewLogPath();
        await File.WriteAllTextAsync(path, "VNCSConnST: closing 192.0.2.73::51038: Authentication failure\n");
        var collector = NewCollector(new LinuxVncCollectorOptions { Source = "Files", LogFiles = [path] });
        Assert.Empty(await collector.ReadAsync(DateTimeOffset.UtcNow));
    }

    [Fact]
    public async Task RotatedSameOffsetAndEndpointWithNewDateRemainsANewEvent()
    {
        var path = NewLogPath();
        var now = DateTimeOffset.Now;
        const string failure = "VNCSConnST: closing 192.0.2.73::51038: Authentication failure\n";
        await File.WriteAllTextAsync(path, NativeDate(now) + "\n" + failure);
        var collector = NewCollector(new LinuxVncCollectorOptions { Source = "Files", LogFiles = [path] });
        var first = Assert.Single(await collector.ReadAsync(now));
        await File.WriteAllTextAsync(path, NativeDate(now.AddSeconds(2)) + "\n" + failure);
        var events = await collector.ReadAsync(now.AddSeconds(2));
        Assert.Equal(2, events.Count);
        Assert.Equal(2, events.Select(item => item.RawEventId).Distinct().Count());
        Assert.Contains(events, item => item.RawEventId == first.RawEventId);
    }

    private static TigerVncLoginParser CreateParser()
    {
        var parser = new TigerVncLoginParser();
        parser.Parse(DateHeader, "fixture", "date");
        parser.Parse("vncext: Listening for VNC connections on 192.0.2.72 interface(s),", "fixture", "listen");
        parser.Parse("port 5901", "fixture", "port");
        return parser;
    }

    private static LinuxVncLoginCollector NewCollector(LinuxVncCollectorOptions options) => new(Microsoft.Extensions.Options.Options.Create(options), NullLogger<LinuxVncLoginCollector>.Instance);
    private static string NativeDate(DateTimeOffset timestamp) => timestamp.LocalDateTime.ToString("ddd MMM d HH:mm:ss yyyy", CultureInfo.InvariantCulture);
    private static string NewLogPath() => Path.Combine(Path.GetTempPath(), $"ipban-vnc-test-{Guid.NewGuid():N}.log");
    private static string Journal(string cursor, string pid, string message) =>
        $$"""{"__CURSOR":"{{cursor}}","_PID":"{{pid}}","_COMM":"Xvnc","__REALTIME_TIMESTAMP":"1762500000000000","MESSAGE":"{{JsonEncodedText.Encode(message)}}"}""";
}
