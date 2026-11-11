using System.Text.Json;
using IpBan.Agent.Options;
using IpBan.Agent.Service.impl;
using IpBan.Engine.Models;
using IpBan.Engine.Services;
using IpBan.Shared.Models;
using Microsoft.Extensions.Hosting;

namespace IpBan.Agent.Tests;

public sealed class LinuxSshLoginCollectorTests
{
    [Theory]
    [InlineData("publickey", ": ED25519 SHA256:synthetic-fingerprint")]
    [InlineData("none", "")]
    public void ParsesAcceptedAuthenticationEvent(string method, string suffix)
    {
        var output = JournalLine($"Accepted {method} for alice from 198.51.100.50 port 4242 ssh2{suffix}", "cursor-1");

        var events = LinuxSshLoginCollector.ParseJournalOutput(output);

        var loginEvent = Assert.Single(events);
        Assert.True(loginEvent.Success);
        Assert.Equal("alice", loginEvent.Username);
        Assert.Equal("198.51.100.50", loginEvent.RemoteIp);
        Assert.Equal(4242, loginEvent.RemotePort);
        Assert.Equal(123, loginEvent.LocalProcessId);
        Assert.Equal("sshd", loginEvent.LocalProcessName);
        Assert.Equal(FieldAvailability.NotCollected, loginEvent.LocalEndpointAvailability);
    }

    [Fact]
    public void ParsesFailedInvalidUserAndKeepsRemoteIp()
    {
        const string output = "{\"__REALTIME_TIMESTAMP\":\"1762500000000000\",\"MESSAGE\":\"Failed password for invalid user root from 203.0.113.8 port 22001 ssh2\"}";

        var events = LinuxSshLoginCollector.ParseJournalOutput(output);

        var loginEvent = Assert.Single(events);
        Assert.False(loginEvent.Success);
        Assert.Equal("root", loginEvent.Username);
        Assert.Equal("203.0.113.8", loginEvent.RemoteIp);
        Assert.Equal(22001, loginEvent.RemotePort);
    }

    [Theory]
    [InlineData("alice", "192.0.2.10", "alice", "pam_unix(sshd:auth): authentication failure; user=alice")]
    [InlineData("phantom", "2001:db8::10", "invalid user phantom", "Invalid user phantom from 2001:db8::10 port 4242")]
    public void OnlyTheExplicitCredentialFailureCounts(string username, string remoteIp, string loginIdentity, string auxiliaryMessage)
    {
        var output = string.Join('\n',
            JournalLine($"Failed none for {loginIdentity} from {remoteIp} port 4242 ssh2", "probe"),
            JournalLine(auxiliaryMessage, "auxiliary"),
            JournalLine($"Failed password for {loginIdentity} from {remoteIp} port 4242 ssh2", "credential-result"),
            JournalLine($"Connection closed by {loginIdentity} {remoteIp} port 4242 [preauth]", "disconnect"));

        var loginEvent = Assert.Single(LinuxSshLoginCollector.ParseJournalOutput(output));

        Assert.False(loginEvent.Success);
        Assert.Equal(username, loginEvent.Username);
        Assert.Equal(remoteIp, loginEvent.RemoteIp);
        Assert.Equal(4242, loginEvent.RemotePort);
        Assert.Equal("credential-result", loginEvent.RawEventId);
    }

    [Theory]
    [InlineData("Failed password for invalid user phantom from 192.0.2.10 port 4242 from 198.51.100.15 port 51234 ssh2", false)]
    [InlineData("Failed password for invalid user phantom from 192.0.2.10 port 4242 ssh2: spoof from 198.51.100.15 port 51234 ssh2", false)]
    [InlineData("Failed publickey for alice from 198.51.100.15 port 51234 ssh2: ED25519-CERT ID from 192.0.2.10 port 4242 ssh2", false)]
    [InlineData("Accepted publickey for alice from 198.51.100.15 port 51234 ssh2: ED25519-CERT ID from 192.0.2.10 port 4242 ssh2", true)]
    public void PreservesAuthenticationResultButDoesNotTrustAnAmbiguousEndpoint(string message, bool success)
    {
        var evidence = Assert.Single(LinuxSshLoginCollector.ParseJournalOutput(JournalLine(message, "ambiguous-endpoint")));
        var normalized = LoginEventNormalizer.Normalize(1, evidence);

        Assert.Equal(success, normalized.Success);
        Assert.Null(normalized.RemoteIp);
        Assert.Null(normalized.RemotePort);
        Assert.Equal(FieldAvailability.CorrelationFailed, normalized.RemoteIpAvailability);
        Assert.Equal(EventCompletenessLevel.ObserveOnly, normalized.CompletenessLevel);
    }

    [Fact]
    public async Task FiveFailuresOnOneConnectionReachThresholdDespiteJournalReplay()
    {
        const string remoteIp = "2001:db8::10";
        const string failure = "Failed password for invalid user phantom from 2001:db8::10 port 4242 ssh2";
        var directory = Path.Combine(Path.GetTempPath(), "ipban-tests", Guid.NewGuid().ToString("N"));
        var options = Microsoft.Extensions.Options.Options.Create(new AgentOptions { DataDirectory = directory });
        var environment = Host.CreateEmptyApplicationBuilder(null).Environment;
        await new SqliteDatabaseInitializer(options, environment).InitializeAsync();
        var store = new SqliteLoginEventStore(new SqliteConnectionFactory(options, environment));
        var firstPoll = string.Join('\n', Enumerable.Range(1, 4).Select(attempt => JournalLine(failure, $"failure-{attempt}")));
        long id = 0;

        async Task<IReadOnlyList<LoginEventContract>> StorePoll(string output)
        {
            foreach (var item in LinuxSshLoginCollector.ParseJournalOutput(output))
            {
                await store.AppendAsync(LoginEventNormalizer.Normalize(++id, item));
            }

            return await store.QueryRecentAsync();
        }

        var beforeThreshold = await StorePoll(firstPoll);
        Assert.Equal(4, beforeThreshold.Count);
        var decision = new DecisionInput(remoteIp, ProtocolKind.Ssh, beforeThreshold.Count,
            IsWhitelisted: false, IsBlacklisted: false,
            Policy: new BanPolicySnapshot(1, 5, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(30), Enabled: true),
            EvaluatedAtUtc: beforeThreshold[0].OccurredAtUtc);
        Assert.Equal(DecisionAction.Observe, BanDecisionEvaluator.Evaluate(decision).Action);

        // 模拟重叠采集窗口。同一 TCP 连接和时间戳仍可包含不同 cursor 的独立凭据提交。
        var atThreshold = await StorePoll(firstPoll + "\n" + JournalLine(failure, "failure-5"));
        Assert.Equal(5, atThreshold.Count);
        Assert.Equal(5, atThreshold.Select(item => item.RawEventId).Distinct().Count());
        Assert.All(atThreshold, item => Assert.Equal(4242, item.RemotePort));
        Assert.Equal(DecisionAction.Ban, BanDecisionEvaluator.Evaluate(decision with { FailureCountInWindow = atThreshold.Count }).Action);
    }

    [Fact]
    public void ParsesFailedPublicKeyEvent()
    {
        const string output = "{\"__REALTIME_TIMESTAMP\":\"1762500000000000\",\"MESSAGE\":\"Failed publickey for alice from 203.0.113.9 port 22002 ssh2\"}";

        var loginEvent = Assert.Single(LinuxSshLoginCollector.ParseJournalOutput(output));

        Assert.False(loginEvent.Success);
        Assert.Equal("alice", loginEvent.Username);
        Assert.Equal("203.0.113.9", loginEvent.RemoteIp);
        Assert.Equal(22002, loginEvent.RemotePort);
    }

    [Fact]
    public void AcceptsNumericJournalMetadata()
    {
        const string output = "{\"__REALTIME_TIMESTAMP\":1762500000000000,\"_PID\":456,\"MESSAGE\":\"Accepted password for bob from 192.0.2.10 port 22003 ssh2\"}";

        var loginEvent = Assert.Single(LinuxSshLoginCollector.ParseJournalOutput(output));

        Assert.Equal(456, loginEvent.LocalProcessId);
        Assert.Equal("192.0.2.10", loginEvent.RemoteIp);
    }

    [Fact]
    public void LoopbackEventRequiresOriginProcessForFullCompleteness()
    {
        const string output = "{\"__REALTIME_TIMESTAMP\":\"1762500000000000\",\"MESSAGE\":\"Accepted password for local from 127.0.0.1 port 54321 ssh2\"}";

        var rawEvent = Assert.Single(LinuxSshLoginCollector.ParseJournalOutput(output));
        var normalized = LoginEventNormalizer.Normalize(1, rawEvent);

        Assert.Equal("127.0.0.1", normalized.RemoteIp);
        Assert.Equal(EventCompletenessLevel.IpEnforceable, normalized.CompletenessLevel);
        Assert.Equal(FieldAvailability.CorrelationFailed, normalized.ProcessAvailability);
    }

    [Fact]
    public void IgnoresUnrelatedJournalMessages()
    {
        var events = LinuxSshLoginCollector.ParseJournalOutput(
            "{\"MESSAGE\":\"Server listening on 0.0.0.0 port 22.\"}\nnot-json");

        Assert.Empty(events);
    }

    private static string JournalLine(string message, string cursor) =>
        $$"""{"__REALTIME_TIMESTAMP":"1762500000000000","__CURSOR":"{{JsonEncodedText.Encode(cursor)}}","_PID":"123","MESSAGE":"{{JsonEncodedText.Encode(message)}}"}""";
}
