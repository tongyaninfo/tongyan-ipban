using IpBan.Shared.Service;

namespace IpBan.Agent.Workers;

/// <summary>
/// 在 Agent 启动阶段强制构造 ID 服务，尽早发现缺失或冲突的 WorkerId 配置。
/// </summary>
public sealed class IdGenerationInitializationHostedService(IIdService idService) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        _ = idService.NewId;
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
