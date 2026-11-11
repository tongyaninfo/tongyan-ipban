using IpBan.Agent.Options;
using IpBan.Shared.Service;
using Microsoft.Extensions.Options;
using Yitter.IdGenerator;

namespace IpBan.Agent.Service.impl;

/// <summary>
/// Agent 进程内的 YiteId/Yitter 发号实现。YitIdHelper 是进程级静态状态，WorkerId 只能初始化一次。
/// </summary>
public sealed class YiteIdService : IIdService
{
    private static readonly object SyncRoot = new();
    private static int? configuredWorkerId;

    public YiteIdService(IOptions<IdGenerationOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var generatorOptions = options.Value.CreateGeneratorOptions();
        lock (SyncRoot)
        {
            if (configuredWorkerId is null)
            {
                YitIdHelper.SetIdGenerator(generatorOptions);
                configuredWorkerId = options.Value.WorkerId;
            }
            else if (configuredWorkerId != options.Value.WorkerId)
            {
                throw new InvalidOperationException(
                    $"当前进程已使用 WorkerId={configuredWorkerId}，不能再次使用 WorkerId={options.Value.WorkerId}。 ");
            }
        }
    }

    public long NewId => YitIdHelper.NextId();
}
