using IpBan.Shared.Models;

namespace IpBan.Agent.Service.impl;

public sealed class IptablesFirewallProvider(IFirewallCommandRunner commandRunner)
    : CommandBasedFirewallProvider(commandRunner)
{
    public override string Name => "iptables";

    public override string Platform => "linux";

    public override FirewallCapabilities Capabilities { get; } = new(
        "iptables",
        "linux",
        SupportsBan: true,
        SupportsUnban: true,
        SupportsCidr: true,
        SupportsExistingConnectionTermination: false,
        RequiresElevatedPrivileges: true);

    protected override FirewallCommand DetectionCommand => new("iptables", ["-L", "INPUT", "-n"]);

    protected override bool IsEnabled(FirewallCommandResult result) => result.Succeeded;

    protected override FirewallCommand CreateBanCommand(string normalizedAddress) =>
        new(FirewallAddressValidator.IsIpv6(normalizedAddress) ? "ip6tables" : "iptables", ["-I", "INPUT", "-s", normalizedAddress, "-j", "DROP"]);

    protected override FirewallCommand CreateUnbanCommand(string normalizedAddress) =>
        new(FirewallAddressValidator.IsIpv6(normalizedAddress) ? "ip6tables" : "iptables", ["-D", "INPUT", "-s", normalizedAddress, "-j", "DROP"]);
}
