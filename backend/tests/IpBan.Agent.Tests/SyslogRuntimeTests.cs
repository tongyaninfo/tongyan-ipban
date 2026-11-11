using System.Net;
using System.Net.Sockets;
using System.Text;
using IpBan.Shared.Logging.Syslog;
using Microsoft.Extensions.DependencyInjection;

namespace IpBan.Agent.Tests;

public sealed class SyslogRuntimeTests
{
    [Fact]
    public async Task EmergencyAndPriorityUnbanBypassSeverityFilterAndSendFirst()
    {
        using var receiver = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var target = Target((IPEndPoint)receiver.Client.LocalEndPoint!, "udp") with { MaxSeverity = 3 };
        var settings = new SyslogSettings(true, "revision", [target]);
        await using var services = CreateServices(NewDirectory(), settings);
        var runtime = services.GetRequiredService<SyslogRuntime>();
        runtime.Apply(settings);
        runtime.Publish("ipban-runtime", "worker.error", SyslogSeverity.Error, "普通错误。");
        runtime.Publish("ipban-runtime", "worker.debug", SyslogSeverity.Debug, "不应转发的诊断。");
        runtime.Publish("ipban-login", "host.login.failure", SyslogSeverity.Emergency, "登录失败。");
        runtime.Publish("ipban-unban", "unban.result", SyslogSeverity.Notice, "解除封禁。", priority: true);

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(12));
        await runtime.StartAsync(timeout.Token);
        try
        {
            var login = await ReadDatagramAsync(receiver, timeout.Token);
            var unban = await ReadDatagramAsync(receiver, timeout.Token);
            var normal = await ReadDatagramAsync(receiver, timeout.Token);
            Assert.StartsWith("<128>1 ", login, StringComparison.Ordinal);
            Assert.Contains("syslog-SYNTHETIC ipban-login", login, StringComparison.Ordinal);
            Assert.StartsWith("<133>1 ", unban, StringComparison.Ordinal);
            Assert.Contains("ipban-unban", unban, StringComparison.Ordinal);
            Assert.StartsWith("<131>1 ", normal, StringComparison.Ordinal);
            Assert.Equal(0, runtime.Snapshot().PriorityDroppedCount);
        }
        finally { await runtime.StopAsync(timeout.Token); }
    }

    [Fact]
    public async Task PendingSegmentSurvivesRestartAndDoesNotFollowNewDestinationVersion()
    {
        using var reserved = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        reserved.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var target = Target((IPEndPoint)reserved.LocalEndPoint!, "tcp");
        var settings = new SyslogSettings(true, "revision", [target]);
        var directory = NewDirectory();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await using (var first = CreateServices(directory, settings))
        {
            var runtime = first.GetRequiredService<SyslogRuntime>();
            runtime.Apply(settings);
            runtime.Publish("ipban-ban", "ban.manual.result", SyslogSeverity.Emergency, "防火墙封禁已生效。");
            await runtime.StartAsync(timeout.Token);
            try
            {
                await WaitAsync(() => runtime.Snapshot().Targets.Any(x => x.QueuedCount == 1 && x.FailedCount > 0), timeout.Token);
            }
            finally { await runtime.StopAsync(timeout.Token); }
        }

        reserved.Listen(4);
        var changed = settings with
        {
            ConfigRevision = "revision2",
            Targets = [target with { DeliveryTargetVersion = "version2" }]
        };
        await using (var second = CreateServices(directory, changed))
        {
            var runtime = second.GetRequiredService<SyslogRuntime>();
            runtime.Apply(changed);
            await runtime.StartAsync(timeout.Token);
            try
            {
                await WaitAsync(() => runtime.Snapshot().Targets.Any(x => x.State == "paused" && x.QueuedCount == 1), timeout.Token);
                Assert.False(reserved.Poll(0, SelectMode.SelectRead));
            }
            finally { await runtime.StopAsync(timeout.Token); }
        }

        await using var third = CreateServices(directory, settings);
        var recovered = third.GetRequiredService<SyslogRuntime>();
        await recovered.StartAsync(timeout.Token);
        try
        {
            using var peer = await reserved.AcceptAsync(timeout.Token);
            using var stream = new NetworkStream(peer);
            // 按 TCP octet-counting 读取完整中文报文，避免把一次 read 当一帧。
            var lengthText = new StringBuilder();
            var next = new byte[1];
            do
            {
                await stream.ReadExactlyAsync(next, timeout.Token);
                if (next[0] != ' ') lengthText.Append((char)next[0]);
            } while (next[0] != ' ' && lengthText.Length <= 8);
            var length = int.Parse(lengthText.ToString(), System.Globalization.CultureInfo.InvariantCulture);
            var data = new byte[length];
            await stream.ReadExactlyAsync(data, timeout.Token);
            var text = Encoding.UTF8.GetString(data);
            Assert.Contains("ipban-ban", text, StringComparison.Ordinal);
            Assert.Contains("防火墙封禁已生效", text, StringComparison.Ordinal);
            await WaitAsync(() => recovered.Snapshot().Targets.Any(x => x.QueuedCount == 0 && x.LastSentAtUtc.HasValue), timeout.Token);
        }
        finally { await recovered.StopAsync(timeout.Token); }
    }

    private static SyslogTarget Target(IPEndPoint endPoint, string protocol) =>
        new("target", "version", "隔离测试目标", endPoint.Address.ToString(), endPoint.Port, protocol);

    private static string NewDirectory() => Path.Combine(Path.GetTempPath(), $"ipban-syslog-test-{Guid.NewGuid():N}");

    private static ServiceProvider CreateServices(string directory, SyslogSettings settings)
    {
        var services = new ServiceCollection();
        services.AddSingleton<ISyslogSettingsReader>(new Reader(settings));
        services.AddLogging(logging => services.AddIpBanSyslog(logging, "agent", directory, "SYNTHETIC"));
        return services.BuildServiceProvider();
    }

    private static async Task<string> ReadDatagramAsync(UdpClient receiver, CancellationToken token) =>
        Encoding.UTF8.GetString((await receiver.ReceiveAsync(token)).Buffer);

    private static async Task WaitAsync(Func<bool> predicate, CancellationToken token)
    {
        while (!predicate()) await Task.Delay(40, token);
    }

    private sealed class Reader(SyslogSettings settings) : ISyslogSettingsReader
    {
        public Task<SyslogSettings> ReadAsync(CancellationToken cancellationToken) => Task.FromResult(settings);
    }
}
