using IpBan.Agent.Service;
using IpBan.Agent.Service.impl;
using IpBan.Shared.Models;

namespace IpBan.Agent.Tests;

public sealed class WindowsConnectionProviderTests
{
    [Fact]
    public void Parse只返回带远端端点的Tcp连接并规范化Established状态()
    {
        var output = $"""
            
              TCP    192.0.2.73:22    198.51.100.10:54123    ESTABLISHED    {Environment.ProcessId}
              TCP    0.0.0.0:22           0.0.0.0:0              LISTENING      4
            """;

        var result = WindowsConnectionSnapshotProvider.Parse(
            output,
            DateTimeOffset.UtcNow);

        var connection = Assert.Single(result);
        Assert.Equal("ESTAB", connection.State);
        Assert.Equal("198.51.100.10", connection.RemoteIp);
        Assert.Equal(54123, connection.RemotePort);
        Assert.Equal("192.0.2.73", connection.LocalIp);
        Assert.Equal(22, connection.LocalPort);
        Assert.Equal(Environment.ProcessId, connection.ProcessId);
    }

    [Fact]
    public async Task Terminator按四元组调用RemoveNetTcpConnection()
    {
        var runner = new RecordingCommandRunner();
        var terminator = new WindowsConnectionTerminator(runner);
        var connection = new ConnectionSnapshotContract(
            "tcp",
            "ESTAB",
            "198.51.100.10",
            54123,
            "192.0.2.73",
            22,
            1234,
            "sshd",
            DateTimeOffset.UtcNow);

        var result = await terminator.TerminateExplicitAsync([connection]);

        Assert.True(result.Success);
        Assert.Equal(1, result.Attempted);
        Assert.Equal(1, result.Terminated);
        Assert.NotNull(runner.Command);
        Assert.Equal("powershell.exe", runner.Command!.FileName);
        var script = runner.Command.Arguments[^1];
        Assert.Contains("-LocalAddress '192.0.2.73'", script, StringComparison.Ordinal);
        Assert.Contains("-RemoteAddress '198.51.100.10'", script, StringComparison.Ordinal);
        Assert.Contains("Remove-NetTCPConnection", script, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ExactDisconnectNeverFallsBackToProcessTermination()
    {
        var runner = new RecordingCommandRunner();
        var terminator = new WindowsConnectionTerminator(runner);
        // IPv6 不会进入 IPv4 的 SetTcpEntry P/Invoke，测试只记录合成命令。
        var connection = new ConnectionSnapshotContract("tcp", "ESTAB", "2001:db8::2", 54123,
            "2001:db8::1", 5986, 1234, "wsmprovhost", DateTimeOffset.UtcNow);

        var result = await terminator.TerminateExactAsync(connection);

        Assert.True(result.Success);
        Assert.NotNull(runner.Command);
        var script = runner.Command.Arguments[^1];
        Assert.Contains("-LocalAddress '2001:db8::1' -LocalPort 5986 -RemoteAddress '2001:db8::2' -RemotePort 54123",
            script, StringComparison.Ordinal);
        Assert.DoesNotContain("Stop-Process", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Get-Process", script, StringComparison.Ordinal);
    }

    private sealed class RecordingCommandRunner : IFirewallCommandRunner
    {
        public FirewallCommand? Command { get; private set; }

        public Task<FirewallCommandResult> ExecuteAsync(
            FirewallCommand command,
            TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            Command = command;
            return Task.FromResult(new FirewallCommandResult(0, string.Empty, string.Empty));
        }
    }
}
