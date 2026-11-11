using IpBan.Shared.Models;

namespace IpBan.Agent.Service;

/// <summary>
/// 平台登录采集器只负责读取原始证据；ID 生成和事件持久化由上层编排服务负责。
/// </summary>
public interface ILoginEventCollector
{
    string Name { get; }

    ProtocolKind Protocol { get; }

    Task<IReadOnlyList<RawLoginEventInput>> CollectAsync(
        DateTimeOffset sinceUtc,
        CancellationToken cancellationToken = default);
}
