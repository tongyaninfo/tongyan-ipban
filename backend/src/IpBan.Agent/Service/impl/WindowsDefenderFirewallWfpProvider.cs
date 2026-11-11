using IpBan.Shared.Models;

namespace IpBan.Agent.Service.impl;

/// <summary>
/// Windows Defender Firewall 是 WFP 的系统管理入口；现有连接断开仍由会话服务单独处理。
/// </summary>
public sealed class WindowsDefenderFirewallWfpProvider(IFirewallCommandRunner commandRunner)
    : CommandBasedFirewallProvider(commandRunner)
{
    public override string Name => "windows-defender-firewall-wfp";

    public override string Platform => "windows";

    public override FirewallCapabilities Capabilities { get; } = new(
        "windows-defender-firewall-wfp",
        "windows",
        SupportsBan: true,
        SupportsUnban: true,
        SupportsCidr: true,
        SupportsExistingConnectionTermination: false,
        RequiresElevatedPrivileges: true);

    protected override FirewallCommand DetectionCommand => new(
        "netsh",
        ["advfirewall", "show", "allprofiles", "state"]);

    protected override bool IsEnabled(FirewallCommandResult result) =>
        result.Succeeded
        && (result.StandardOutput.Contains("ON", StringComparison.OrdinalIgnoreCase)
            || result.StandardOutput.Contains("启用", StringComparison.OrdinalIgnoreCase));

    protected override FirewallCommand CreateBanCommand(string normalizedAddress) =>
        new(
            "netsh",
            [
                "advfirewall",
                "firewall",
                "add",
                "rule",
                $"name={RuleName(normalizedAddress)}",
                "dir=in",
                "action=block",
                $"remoteip={normalizedAddress}",
                "profile=any"
            ]);

    protected override FirewallCommand CreateUnbanCommand(string normalizedAddress) =>
        new(
            "netsh",
            [
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                $"name={RuleName(normalizedAddress)}"
            ]);
}
