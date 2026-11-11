using IpBan.Agent.Service;
using IpBan.Shared.Models;
using IpBan.Shared.Logging.Syslog;

namespace IpBan.Agent.Workers;

/// <summary>
/// Agent 启动时探测宿主防火墙。探测只读取状态，不恢复防火墙，也不补写历史动作。
/// </summary>
public sealed partial class FirewallProviderDetectionHostedService(
    IFirewallProviderSelector selector,
    ILogger<FirewallProviderDetectionHostedService> logger,
    SyslogRuntime? syslog = null) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var platform = OperatingSystem.IsWindows()
            ? "windows"
            : OperatingSystem.IsLinux()
                ? "linux"
                : "unsupported";

        if (platform == "unsupported")
        {
            LogUnsupportedPlatform(platform);
            return;
        }

        try
        {
            var selection = await selector.SelectAsync(platform, cancellationToken).ConfigureAwait(false);
            var status = selection.Observation.Status;
            syslog?.Publish("ipban-firewall", "firewall.probe",
                status == FirewallStatus.Enabled ? SyslogSeverity.Notice : SyslogSeverity.Warning,
                status == FirewallStatus.Enabled ? "检测到防火墙已启用。" : "防火墙未就绪，封禁保护处于降级状态。",
                result: status.ToString());
        }
        catch (Exception exception) when (exception is InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            // 探测失败不阻断事件采集；后续封禁动作必须保留 Failed/ProtectionDegraded 状态。
            LogDetectionFailed(exception.GetType().Name);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    [LoggerMessage(Level = LogLevel.Information, Message = "宿主平台 {platform} 不在首期 Windows/Linux 防火墙支持范围内")]
    private partial void LogUnsupportedPlatform(string platform);

    [LoggerMessage(Level = LogLevel.Warning, Message = "防火墙 Provider 探测失败，事件采集继续运行：{message}")]
    private partial void LogDetectionFailed(string message);
}
