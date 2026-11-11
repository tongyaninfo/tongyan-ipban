using IpBan.Shared.Logging.Syslog;

namespace IpBan.Agent;

public sealed partial class Worker(ILogger<Worker> logger, SyslogRuntime? syslog = null) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // 采集、持久化、防火墙探测和 IPC 由独立 HostedService 管理；此任务只负责宿主心跳。
        syslog?.Publish("ipban-runtime", "agent.started", SyslogSeverity.Notice, "IPBan Agent 已启动。");
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                LogHeartbeat(DateTimeOffset.UtcNow);
                await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally
        {
            syslog?.Publish("ipban-runtime", "agent.stopped", SyslogSeverity.Notice, "IPBan Agent 正常停止。");
        }
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "IPBan Agent 心跳时间：{time}")]
    private partial void LogHeartbeat(DateTimeOffset time);
}
