namespace IpBan.Shared.Service;

/// <summary>
/// 业务 ID 抽象。具体发号算法由宿主配置，业务代码不直接依赖 Yitter API。
/// </summary>
public interface IIdService
{
    long NewId { get; }
}
