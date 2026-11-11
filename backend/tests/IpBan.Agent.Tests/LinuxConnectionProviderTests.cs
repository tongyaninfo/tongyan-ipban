using System.Globalization;
using IpBan.Agent.Service;
using IpBan.Agent.Service.impl;
using IpBan.Shared.Models;

namespace IpBan.Agent.Tests;

public sealed class LinuxConnectionProviderTests
{
    [Fact]
    public async Task QueryUsesSsStructuredArgumentsAndParsesProcessAndEndpoints()
    {
        var runner = new FakeRunner(_ => new FirewallCommandResult(
            0,
            "ESTAB 0 0 127.0.0.1:22 127.0.0.1:45678 users:((\"sshd\",pid=123,fd=4))\n",
            string.Empty));
        var provider = new LinuxConnectionSnapshotProvider(runner);

        var snapshots = await provider.QueryAsync();

        var snapshot = Assert.Single(snapshots);
        Assert.Equal("tcp", snapshot.Protocol);
        Assert.Equal("ESTAB", snapshot.State);
        Assert.Equal("127.0.0.1", snapshot.RemoteIp);
        Assert.Equal(45678, snapshot.RemotePort);
        Assert.Equal("127.0.0.1", snapshot.LocalIp);
        Assert.Equal(22, snapshot.LocalPort);
        Assert.Equal(123, snapshot.ProcessId);
        Assert.Equal("sshd", snapshot.ProcessName);
        var command = Assert.Single(runner.Commands);
        Assert.Equal("ss", command.FileName);
        Assert.Equal(["-tnpH"], command.Arguments);
    }

    [Fact]
    public void ParseSupportsBracketedIpv6AndSkipsIncompleteRemoteEndpoint()
    {
        var output = string.Join('\n',
            "ESTAB 0 0 [::1]:22 [::1]:45678 users:((\"sshd\",pid=321,fd=4))",
            "LISTEN 0 128 *:22 *:* users:((\"sshd\",pid=321,fd=3))");

        var snapshots = LinuxConnectionSnapshotProvider.Parse(
            output,
            DateTimeOffset.Parse("2026-11-07T00:00:00Z", CultureInfo.InvariantCulture));

        var snapshot = Assert.Single(snapshots);
        Assert.Equal("::1", snapshot.RemoteIp);
        Assert.Equal(45678, snapshot.RemotePort);
        Assert.Equal("::1", snapshot.LocalIp);
        Assert.Equal(22, snapshot.LocalPort);
        Assert.Equal("sshd", snapshot.ProcessName);
    }

    private sealed class FakeRunner(
        Func<FirewallCommand, FirewallCommandResult> resultFactory) : IFirewallCommandRunner
    {
        public List<FirewallCommand> Commands { get; } = [];

        public Task<FirewallCommandResult> ExecuteAsync(
            FirewallCommand command,
            TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            Commands.Add(command);
            return Task.FromResult(resultFactory(command));
        }
    }
}

public sealed class LinuxConnectionTerminatorTests
{
    [Fact]
    public async Task ExactDisconnectLimitsCommandToOneEstablishedTcpTuple()
    {
        var runner = new FakeRunner(_ => new FirewallCommandResult(0, string.Empty, string.Empty));
        var terminator = new LinuxConnectionTerminator(runner);
        var connection = new ConnectionSnapshotContract(
            "tcp", "ESTAB", "192.0.2.10", 45678, "192.0.2.1", 22, 123, "sshd", DateTimeOffset.UtcNow);

        var result = await terminator.TerminateExactAsync(connection);

        Assert.True(result.Success);
        var command = Assert.Single(runner.Commands);
        Assert.Equal("ss", command.FileName);
        Assert.Equal(
            ["-K", "-t", "state", "established", "src", "192.0.2.1", "sport", "=", "22", "dst", "192.0.2.10", "dport", "=", "45678"],
            command.Arguments);
    }

    [Fact]
    public async Task TerminatesOnlyQualifiedConnectionsWithSsKillFilter()
    {
        var runner = new FakeRunner(_ => new FirewallCommandResult(0, string.Empty, string.Empty));
        var terminator = new LinuxConnectionTerminator(runner);
        var connections = new[]
        {
            new ConnectionSnapshotContract(
                "tcp", "ESTAB", "127.0.0.1", 45678, "127.0.0.1", 22, 123, "sshd", DateTimeOffset.UtcNow),
            new ConnectionSnapshotContract(
                "tcp", "ESTAB", "192.0.2.10", null, "192.0.2.1", 22, null, null, DateTimeOffset.UtcNow)
        };

        var result = await terminator.TerminateAsync(connections);

        Assert.True(result.Success);
        Assert.Equal(1, result.Attempted);
        Assert.Equal(1, result.Terminated);
        var command = Assert.Single(runner.Commands);
        Assert.Equal("ss", command.FileName);
        Assert.Equal(
            ["-K", "dst", "127.0.0.1", "sport", "=", "45678", "dport", "=", "22"],
            command.Arguments);
    }

    [Fact]
    public async Task DoesNotRunCommandsWhenNoConnectionHasCompletePorts()
    {
        var runner = new FakeRunner(_ => throw new InvalidOperationException("不应执行命令。"));
        var terminator = new LinuxConnectionTerminator(runner);

        var result = await terminator.TerminateAsync(new[]
        {
            new ConnectionSnapshotContract(
                "tcp", "ESTAB", "127.0.0.1", null, "127.0.0.1", 22, null, null, DateTimeOffset.UtcNow)
        });

        Assert.True(result.Success);
        Assert.Equal(0, result.Attempted);
        Assert.Empty(runner.Commands);
    }

    private sealed class FakeRunner(
        Func<FirewallCommand, FirewallCommandResult> resultFactory) : IFirewallCommandRunner
    {
        public List<FirewallCommand> Commands { get; } = [];

        public Task<FirewallCommandResult> ExecuteAsync(
            FirewallCommand command,
            TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            Commands.Add(command);
            return Task.FromResult(resultFactory(command));
        }
    }
}
