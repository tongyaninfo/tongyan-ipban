using IpBan.Api.Service;
using IpBan.Api.Service.impl;
using Microsoft.Data.Sqlite;

namespace IpBan.Api.Workers;

/// <summary>两个固定消费者隔离慢查询；启动时数据库尚未就绪则延迟读取配置，不阻塞宿主。</summary>
public sealed partial class IpLocationWorker(IpLocationService service, IIPLocation provider, ILogger<IpLocationWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await service.GetSettingsAsync(stoppingToken).ConfigureAwait(false);
                    break;
                }
                catch (Exception exception) when (exception is SqliteException or IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
                {
                    LogConfigurationUnavailable();
                    await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken).ConfigureAwait(false);
                }
            }
            await Task.WhenAll(service.ProcessQueueAsync(provider, stoppingToken), service.ProcessQueueAsync(provider, stoppingToken)).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "IP 解析配置暂不可用，解析保持关闭，稍后重试。")]
    private partial void LogConfigurationUnavailable();
}
