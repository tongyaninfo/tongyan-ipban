using IpBan.Api.Models;

namespace IpBan.Api.Service;

/// <summary>只负责单 IP 的外部查询；业务路径通过队列服务调用，不直接等待此接口。</summary>
public interface IIPLocation
{
    Task<IpLocationResult> ResolveAsync(string ip, IpLocationSettings settings, CancellationToken cancellationToken);
}
