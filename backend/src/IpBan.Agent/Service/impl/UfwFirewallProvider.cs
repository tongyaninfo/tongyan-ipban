using IpBan.Shared.Models;

namespace IpBan.Agent.Service.impl;

public sealed class UfwFirewallProvider(IFirewallCommandRunner commandRunner)
    : CommandBasedFirewallProvider(commandRunner)
{
    public override string Name => "ufw";

    public override string Platform => "linux";

    public override FirewallCapabilities Capabilities { get; } = new(
        "ufw",
        "linux",
        SupportsBan: true,
        SupportsUnban: true,
        SupportsCidr: true,
        SupportsExistingConnectionTermination: false,
        RequiresElevatedPrivileges: true);

    protected override FirewallCommand DetectionCommand => new("ufw", ["status"]);

    protected override bool IsEnabled(FirewallCommandResult result) =>
        result.Succeeded && result.StandardOutput.Contains("Status: active", StringComparison.OrdinalIgnoreCase);

    protected override FirewallCommand CreateBanCommand(string normalizedAddress) =>
        new("ufw", ["--force", "deny", "from", normalizedAddress]);

    protected override FirewallCommand CreateUnbanCommand(string normalizedAddress) =>
        new("ufw", ["--force", "delete", "deny", "from", normalizedAddress]);
}
