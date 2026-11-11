using Microsoft.Data.Sqlite;

namespace IpBan.Api.Service.impl;

public sealed partial class McpAuditPruneWorker(McpStore store, ILogger<McpAuditPruneWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromHours(1));
        do
        {
            try
            {
                // 每轮最多删除五千条，并在每批之间释放事务写锁。
                for (var batch = 0; batch < 10 && !stoppingToken.IsCancellationRequested; batch++)
                {
                    if (await store.PruneAsync(stoppingToken).ConfigureAwait(false) < 500)
                    {
                        break;
                    }
                }
            }
            catch (Exception exception) when (exception is SqliteException or McpStoreException)
            {
                CleanupUnavailable(logger);
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "MCP 审计清理暂不可用，将在下一轮重试。")]
    private static partial void CleanupUnavailable(ILogger logger);
}
