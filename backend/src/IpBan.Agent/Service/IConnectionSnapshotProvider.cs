using IpBan.Shared.Models;

namespace IpBan.Agent.Service;

/// <summary>
/// 查询本机当前 TCP 连接。实现应返回可用于展示和封禁关联的结构化来源信息。
/// </summary>
public interface IConnectionSnapshotProvider
{
    Task<IReadOnlyList<ConnectionSnapshotContract>> QueryAsync(
        CancellationToken cancellationToken = default);
}
