using IpBan.Shared.Models;

namespace IpBan.Agent.Service.impl;

public sealed class FirewalldFirewallProvider(IFirewallCommandRunner commandRunner)
    : CommandBasedFirewallProvider(commandRunner)
{
    public override string Name => "firewalld";

    public override string Platform => "linux";

    public override FirewallCapabilities Capabilities { get; } = new(
        "firewalld",
        "linux",
        SupportsBan: true,
        SupportsUnban: true,
        SupportsCidr: true,
        SupportsExistingConnectionTermination: false,
        RequiresElevatedPrivileges: true);

    protected override FirewallCommand DetectionCommand => new(
        "firewall-cmd",
        ["--state"]);

    protected override bool IsEnabled(FirewallCommandResult result) =>
        result.Succeeded && result.StandardOutput.Trim().Equals("running", StringComparison.OrdinalIgnoreCase);

    protected override FirewallCommand CreateBanCommand(string normalizedAddress) =>
        new("firewall-cmd", DirectRuleCommand("--add-rule", normalizedAddress));

    protected override FirewallCommand CreateUnbanCommand(string normalizedAddress) =>
        new("firewall-cmd", DirectRuleCommand("--remove-rule", normalizedAddress));

    // 这里只写运行时规则。是否安排到期由 Agent 按封禁时长决定。
    private static string[] DirectRuleCommand(string operation, string normalizedAddress)
    {
        var family = FirewallAddressValidator.IsIpv6(normalizedAddress) ? "ipv6" : "ipv4";
        return ["--quiet", "--direct", operation, family, "filter", "INPUT", "0", "-m", "conntrack", "--ctstate", "NEW", "-s", normalizedAddress, "-j", "DROP"];
    }
}
