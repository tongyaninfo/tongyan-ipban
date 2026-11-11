using IpBan.Shared.Models;

namespace IpBan.Agent.Service;

/// <summary>
/// 登录事件持久化合同。采集器只提交已经归一化的事件，仓储不参与封禁判定。
/// </summary>
public interface ILoginEventStore
{
    Task AppendAsync(LoginEventContract loginEvent, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<LoginEventContract>> QueryRecentAsync(
        int limit = 100,
        CancellationToken cancellationToken = default);
}
