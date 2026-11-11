using IpBan.Agent.Service;
using IpBan.Agent.Service.impl;
using IpBan.Shared.Models;

namespace IpBan.Agent.Tests;

public sealed class FirewallProviderTests
{
    [Fact]
    public async Task LinuxSelectorUsesFirewalldBeforeUfw()
    {
        var providers = new IFirewallProvider[]
        {
            new FakeProvider("ufw", "linux", FirewallStatus.Enabled),
            new FakeProvider("firewalld", "linux", FirewallStatus.Enabled)
        };
        var selector = new FirewallProviderSelector(providers);

        var selection = await selector.SelectAsync("linux");

        Assert.NotNull(selection.Provider);
        Assert.Equal("firewalld", selection.Provider!.Name);
        var probe = Assert.Single(selection.Probes);
        Assert.Equal("firewalld", probe.Provider);
    }

    [Fact]
    public async Task InvalidSourceAddressIsRejectedBeforeCommandExecution()
    {
        var runner = new FakeRunner(_ => new FirewallCommandResult(0, "running", string.Empty));
        var provider = new FirewalldFirewallProvider(runner);

        var result = await provider.BanAsync("192.0.2.10; rm -rf /");

        Assert.Equal(FirewallActionStatus.Failed, result.ActionStatus);
        Assert.Equal("FIREWALL_INVALID_SOURCE", result.ErrorCode);
        Assert.Empty(runner.Commands);
    }

    [Fact]
    public async Task FirewalldBanUsesStructuredArgumentsAndCanonicalAddress()
    {
        var runner = new FakeRunner(command => command.Arguments[0] == "--state"
            ? new FirewallCommandResult(0, "running", string.Empty)
            : new FirewallCommandResult(0, string.Empty, string.Empty));
        var provider = new FirewalldFirewallProvider(runner);

        var result = await provider.BanAsync(" 192.0.2.10/24 ");

        Assert.Equal(FirewallActionStatus.Applied, result.ActionStatus);
        var banCommands = runner.Commands.Skip(1).Where(command => command.Arguments.Contains("--direct")).ToArray();
        var banCommand = Assert.Single(banCommands);
        Assert.Equal("firewall-cmd", banCommand.FileName);
        Assert.Contains("192.0.2.10/24", banCommand.Arguments);
        Assert.DoesNotContain("--permanent", banCommand.Arguments);
        Assert.DoesNotContain(";", string.Join(' ', banCommand.Arguments));
    }

    [Fact]
    public async Task PermissionFailureIsReportedAsDegraded()
    {
        var runner = new FakeRunner(command => command.Arguments[0] == "--state"
            ? new FirewallCommandResult(0, "running", string.Empty)
            : new FirewallCommandResult(
                1,
                string.Empty,
                "permission denied",
                WasPermissionDenied: true));
        var provider = new UfwFirewallProvider(runner);

        var result = await provider.BanAsync("198.51.100.2");

        Assert.Equal(FirewallActionStatus.Failed, result.ActionStatus);
        Assert.Equal(FirewallStatus.PermissionDenied, result.FirewallStatus);
        Assert.True(result.ProtectionDegraded);
    }

    [Fact]
    public async Task MissingCommandIsUnsupported()
    {
        var runner = new FakeRunner(_ => new FirewallCommandResult(
            127,
            string.Empty,
            "not found",
            WasNotFound: true));
        var provider = new IptablesFirewallProvider(runner);

        var observation = await provider.DetectAsync();

        Assert.Equal(FirewallStatus.Unsupported, observation.Status);
        Assert.True(observation.ProtectionDegraded);
    }

    [Fact]
    public async Task NftablesBanCreatesDedicatedTableAndChainBeforeRule()
    {
        var runner = new FakeRunner(command => command.Arguments switch
        {
            ["list", "ruleset"] => new FirewallCommandResult(0, "", ""),
            ["list", "table", "inet", "ipban"] => new FirewallCommandResult(1, "", "missing", WasNotFound: true),
            ["list", "chain", "inet", "ipban", "input"] => new FirewallCommandResult(1, "", "missing", WasNotFound: true),
            _ => new FirewallCommandResult(0, "", "")
        });
        var provider = new NftablesFirewallProvider(runner);

        var result = await provider.BanAsync("192.0.2.10");

        Assert.Equal(FirewallActionStatus.Applied, result.ActionStatus);
        Assert.Contains(runner.Commands, command => command.Arguments.SequenceEqual(["add", "table", "inet", "ipban"]));
        Assert.Contains(runner.Commands, command => command.Arguments.SequenceEqual(["add", "chain", "inet", "ipban", "input", "{ type filter hook input priority 0; policy accept; }"]));
        Assert.Contains(runner.Commands, command => command.Arguments.Contains("saddr") && command.Arguments.Contains("192.0.2.10"));
    }

    [Fact]
    public async Task NftablesUnbanDeletesMatchingRuleByHandle()
    {
        var runner = new FakeRunner(command => command.Arguments.SequenceEqual(["-a", "list", "chain", "inet", "ipban", "input"])
            ? new FirewallCommandResult(0, "ip saddr 192.0.2.10 drop # handle 7", string.Empty)
            : new FirewallCommandResult(0, string.Empty, string.Empty));
        var provider = new NftablesFirewallProvider(runner);

        var result = await provider.UnbanAsync("192.0.2.10");

        Assert.Equal(FirewallActionStatus.Removed, result.ActionStatus);
        Assert.Contains(runner.Commands, command => command.Arguments.SequenceEqual(["delete", "rule", "inet", "ipban", "input", "handle", "7"]));
    }

    private sealed class FakeRunner(
        Func<FirewallCommand, FirewallCommandResult> resultFactory) : IFirewallCommandRunner
    {
        public List<FirewallCommand> Commands { get; } = [];

        public Task<FirewallCommandResult> ExecuteAsync(
            FirewallCommand command,
            TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            Commands.Add(command);
            return Task.FromResult(resultFactory(command));
        }
    }

    private sealed class FakeProvider(
        string name,
        string platform,
        FirewallStatus status) : IFirewallProvider
    {
        public string Name => name;

        public string Platform => platform;

        public FirewallCapabilities Capabilities { get; } = new(
            name,
            platform,
            SupportsBan: true,
            SupportsUnban: true,
            SupportsCidr: true,
            SupportsExistingConnectionTermination: false,
            RequiresElevatedPrivileges: true);

        public Task<FirewallObservation> DetectAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(new FirewallObservation(
                Name,
                status,
                status == FirewallStatus.Enabled,
                null,
                DateTimeOffset.UtcNow,
                Capabilities));

        public Task<FirewallActionResult> BanAsync(
            string sourceAddress,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<FirewallActionResult> UnbanAsync(
            string sourceAddress,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }
}
