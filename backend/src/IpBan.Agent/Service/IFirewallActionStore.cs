using IpBan.Shared.Models;
using IpBan.Agent.Models;

namespace IpBan.Agent.Service;

public interface IFirewallActionStore
{
    Task<long> AppendAsync(string action, FirewallActionResult result, CancellationToken cancellationToken = default);

    Task<long> AppendAsync(string action, FirewallActionResult result, FirewallNotificationContext? notificationContext,
        CancellationToken cancellationToken = default);
}
