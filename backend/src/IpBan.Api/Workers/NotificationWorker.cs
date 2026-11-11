using IpBan.Api.Service.impl;

namespace IpBan.Api.Workers;

/// <summary>单独处理邮件投递。异常仅记录脱敏状态，下一轮重试存储，不影响 Agent 的采集和封禁。</summary>
public sealed partial class NotificationWorker(NotificationService service, ILogger<NotificationWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await service.ProcessOnceAsync(stoppingToken).ConfigureAwait(false); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception) { LogNotificationUnavailable(logger); }
            try { await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken).ConfigureAwait(false); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }

    [LoggerMessage(EventId = 7301, Level = LogLevel.Warning, Message = "邮件通知后台处理暂不可用；请检查通知配置、数据库及发送记录。")]
    private static partial void LogNotificationUnavailable(ILogger logger);
}
