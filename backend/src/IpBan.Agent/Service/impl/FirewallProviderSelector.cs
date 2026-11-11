using IpBan.Shared.Models;

namespace IpBan.Agent.Service.impl;

public sealed class FirewallProviderSelector(
    IEnumerable<IFirewallProvider> providers) : IFirewallProviderSelector
{
    private static readonly string[] LinuxPriority = ["firewalld", "ufw", "nftables", "iptables"];

    public async Task<FirewallProviderSelection> SelectAsync(
        string platform,
        CancellationToken cancellationToken = default)
    {
        var candidates = providers
            .Where(provider => provider.Platform.Equals(platform, StringComparison.OrdinalIgnoreCase))
            .OrderBy(provider => Priority(provider.Name, platform))
            .ToArray();

        var probes = new List<FirewallObservation>(candidates.Length);
        foreach (var provider in candidates)
        {
            var observation = await provider.DetectAsync(cancellationToken).ConfigureAwait(false);
            probes.Add(observation);
            if (observation.Status == FirewallStatus.Enabled)
            {
                return new FirewallProviderSelection(provider, observation, probes);
            }
        }

        var fallback = probes.FirstOrDefault(observation => observation.Status != FirewallStatus.Unsupported)
            ?? new FirewallObservation(
                Provider: "none",
                Status: FirewallStatus.Unsupported,
                IsActive: false,
                Detail: $"未发现可用的 {platform} 防火墙 Provider。",
                ObservedAtUtc: DateTimeOffset.UtcNow,
                Capabilities: new FirewallCapabilities(
                    "none",
                    platform,
                    SupportsBan: false,
                    SupportsUnban: false,
                    SupportsCidr: false,
                    SupportsExistingConnectionTermination: false,
                    RequiresElevatedPrivileges: true));

        return new FirewallProviderSelection(null, fallback, probes);
    }

    private static int Priority(string name, string platform)
    {
        if (platform.Equals("linux", StringComparison.OrdinalIgnoreCase))
        {
            var index = Array.IndexOf(LinuxPriority, name);
            return index >= 0 ? index : LinuxPriority.Length;
        }

        return name.Equals("windows-defender-firewall-wfp", StringComparison.OrdinalIgnoreCase) ? 0 : 1;
    }
}
