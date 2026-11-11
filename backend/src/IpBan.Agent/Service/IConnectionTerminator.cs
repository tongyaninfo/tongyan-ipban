using IpBan.Shared.Models;

namespace IpBan.Agent.Service;

/// <summary>
/// 主动断开已建立连接的结果。
/// </summary>
public sealed record ConnectionTerminationResult(
    bool Success,
    int Attempted,
    int Terminated,
    string? Error)
{
    public ConnectionTerminationContract ToContract() =>
        new(Success, Attempted, Terminated, Error);
}

public interface IConnectionTerminator
{
    Task<ConnectionTerminationResult> TerminateAsync(
        IReadOnlyList<ConnectionSnapshotContract> connections,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 用户明确选择“下线”时允许结束快照关联的 SSH/SSHD 进程，弥补部分内核 ss -K 不生效的问题。
    /// </summary>
    Task<ConnectionTerminationResult> TerminateExplicitAsync(
        IReadOnlyList<ConnectionSnapshotContract> connections,
        CancellationToken cancellationToken = default);

    /// <summary>仅操作一个完整 TCP 四元组，禁止使用进程退出作为兜底。</summary>
    Task<ConnectionTerminationResult> TerminateExactAsync(
        ConnectionSnapshotContract connection,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(new ConnectionTerminationResult(false, 0, 0, "当前执行器不支持精确下线。"));
}
