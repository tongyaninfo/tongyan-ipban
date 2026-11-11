using IpBan.Agent.Service;
using IpBan.Shared.Logging.Syslog;

namespace IpBan.Agent.Workers;

/// <summary>
/// 数据库迁移作为 Agent 启动前置任务；迁移失败时让宿主启动失败，避免采集器使用未知结构运行。
/// </summary>
public sealed class DatabaseInitializationHostedService(IDatabaseInitializer initializer, SyslogRuntime? syslog = null) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            var result = await initializer.InitializeAsync(cancellationToken).ConfigureAwait(false);
            if (result.DatabaseCreated || result.CurrentVersion != result.PreviousVersion)
                syslog?.Publish("ipban-storage", "storage.initialized", SyslogSeverity.Notice,
                    $"数据库已就绪，结构版本为 {result.CurrentVersion}。", result: "Success");
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            syslog?.Publish("ipban-storage", "storage.initialization.failed", SyslogSeverity.Critical,
                "数据库初始化失败，Agent 未启动采集和封禁。", result: "Failure");
            throw;
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
