using IpBan.Agent.Workers;
using IpBan.Shared.Models;

namespace IpBan.Agent.Tests;

public sealed class AutomaticBanPolicyTests
{
    [Theory]
    [InlineData(null, ProtocolKind.Rdp)]
    [InlineData("ALL", ProtocolKind.Rdp)]
    [InlineData("all", ProtocolKind.OpenSsh)]
    [InlineData("Ssh", ProtocolKind.OpenSsh)]
    [InlineData("Rdp", ProtocolKind.Rdp)]
    [InlineData(null, ProtocolKind.Vnc)]
    [InlineData("ALL", ProtocolKind.Vnc)]
    [InlineData("Vnc", ProtocolKind.Vnc)]
    public void AllAndProtocolAliasesMatch(string? policyProtocol, ProtocolKind eventProtocol)
    {
        Assert.True(AutomaticBanHostedService.MatchesPolicyProtocol(policyProtocol, eventProtocol));
    }

    [Theory]
    [InlineData("Rdp", ProtocolKind.Ssh)]
    [InlineData("Vnc", ProtocolKind.Rdp)]
    [InlineData("Ssh", ProtocolKind.WinRm)]
    public void DifferentProtocolsDoNotMatch(string policyProtocol, ProtocolKind eventProtocol)
    {
        Assert.False(AutomaticBanHostedService.MatchesPolicyProtocol(policyProtocol, eventProtocol));
    }
}
