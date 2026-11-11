using IpBan.Shared.Models;

namespace IpBan.Agent.Service;

public interface IFirewallProvider
{
    string Name { get; }

    string Platform { get; }

    FirewallCapabilities Capabilities { get; }

    Task<FirewallObservation> DetectAsync(CancellationToken cancellationToken = default);

    Task<FirewallActionResult> BanAsync(
        string sourceAddress,
        CancellationToken cancellationToken = default);

    Task<FirewallActionResult> UnbanAsync(
        string sourceAddress,
        CancellationToken cancellationToken = default);
}

public sealed record FirewallProviderSelection(
    IFirewallProvider? Provider,
    FirewallObservation Observation,
    IReadOnlyList<FirewallObservation> Probes);

public interface IFirewallProviderSelector
{
    Task<FirewallProviderSelection> SelectAsync(
        string platform,
        CancellationToken cancellationToken = default);
}
