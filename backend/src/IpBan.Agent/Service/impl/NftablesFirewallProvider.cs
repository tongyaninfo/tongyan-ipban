using System.Text.RegularExpressions;
using IpBan.Shared.Models;

namespace IpBan.Agent.Service.impl;

public sealed class NftablesFirewallProvider(IFirewallCommandRunner commandRunner)
    : CommandBasedFirewallProvider(commandRunner)
{
    public override string Name => "nftables";

    public override string Platform => "linux";

    public override FirewallCapabilities Capabilities { get; } = new(
        "nftables",
        "linux",
        SupportsBan: true,
        SupportsUnban: true,
        SupportsCidr: true,
        SupportsExistingConnectionTermination: false,
        RequiresElevatedPrivileges: true);

    protected override FirewallCommand DetectionCommand => new("nft", ["list", "ruleset"]);

    protected override bool IsEnabled(FirewallCommandResult result) => result.Succeeded;

    protected override FirewallCommand CreateBanCommand(string normalizedAddress) =>
        new(
            "nft",
            [
                "add",
                "rule",
                "inet",
                "ipban",
                "input",
                FirewallAddressValidator.IsIpv6(normalizedAddress) ? "ip6" : "ip",
                "saddr",
                normalizedAddress,
                "drop"
            ]);

    public override async Task<FirewallActionResult> BanAsync(
        string sourceAddress,
        CancellationToken cancellationToken = default)
    {
        if (!FirewallAddressValidator.TryNormalize(sourceAddress, out var normalizedAddress))
        {
            return new FirewallActionResult(
                Name,
                sourceAddress,
                FirewallActionStatus.Failed,
                FirewallStatus.CommandFailed,
                "FIREWALL_INVALID_SOURCE",
                "来源地址必须是合法 IP 或 CIDR。",
                DateTimeOffset.UtcNow);
        }

        var preparation = await EnsureTableAndChainAsync(cancellationToken).ConfigureAwait(false);
        if (preparation is not null)
        {
            return new FirewallActionResult(
                Name,
                normalizedAddress,
                FirewallActionStatus.Failed,
                preparation.Value.Status,
                preparation.Value.ErrorCode,
                preparation.Value.ErrorMessage,
                DateTimeOffset.UtcNow);
        }

        return await base.BanAsync(normalizedAddress, cancellationToken).ConfigureAwait(false);
    }

    // null 表示无法核实，调用方不能把查询失败当成规则缺失。
    internal async Task<bool?> HasSourceRuleAsync(string sourceAddress, CancellationToken cancellationToken)
    {
        if (!FirewallAddressValidator.TryNormalize(sourceAddress, out var normalizedAddress))
        {
            return null;
        }

        var result = await ReadInputChainAsync(cancellationToken).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            return IsMissingChain(result) ? false : null;
        }

        if (!result.StandardOutput.TrimStart().StartsWith("table inet ipban {", StringComparison.Ordinal)
            || !result.StandardOutput.Contains("chain input {", StringComparison.Ordinal))
        {
            return null;
        }

        return ParseRuleHandles(result.StandardOutput, normalizedAddress).Length > 0;
    }

    public override async Task<FirewallActionResult> UnbanAsync(
        string sourceAddress,
        CancellationToken cancellationToken = default)
    {
        if (!FirewallAddressValidator.TryNormalize(sourceAddress, out var normalizedAddress))
        {
            return new FirewallActionResult(
                Name,
                sourceAddress,
                FirewallActionStatus.Failed,
                FirewallStatus.CommandFailed,
                "FIREWALL_INVALID_SOURCE",
                "来源地址必须是合法 IP 或 CIDR。",
                DateTimeOffset.UtcNow);
        }

        var listResult = await ReadInputChainAsync(cancellationToken).ConfigureAwait(false);
        if (listResult.WasNotFound)
        {
            return FailureResult(normalizedAddress, FirewallStatus.Unsupported, "FIREWALL_UNSUPPORTED", "未找到 nft 命令。");
        }

        if (listResult.WasPermissionDenied)
        {
            return FailureResult(normalizedAddress, FirewallStatus.PermissionDenied, "FIREWALL_PERMISSION_DENIED", "权限不足。");
        }

        if (!listResult.Succeeded)
        {
            // 专属表或链不存在时，来源规则已经不存在，解封按幂等语义视为完成。
            if (IsMissingChain(listResult))
            {
                return RemovedResult(normalizedAddress);
            }

            return FailureResult(normalizedAddress, FirewallStatus.CommandFailed, "FIREWALL_NFT_LIST_FAILED", listResult.StandardError);
        }

        var handles = ParseRuleHandles(listResult.StandardOutput, normalizedAddress);
        foreach (var handle in handles)
        {
            var deleteResult = await CommandRunner.ExecuteAsync(
                new FirewallCommand("nft", ["delete", "rule", "inet", "ipban", "input", "handle", handle]),
                CommandTimeout,
                cancellationToken).ConfigureAwait(false);
            if (!deleteResult.Succeeded)
            {
                return FailureResult(normalizedAddress, FirewallStatus.CommandFailed, "FIREWALL_NFT_DELETE_FAILED", deleteResult.StandardError);
            }
        }

        return RemovedResult(normalizedAddress);
    }

    private Task<FirewallCommandResult> ReadInputChainAsync(CancellationToken cancellationToken) =>
        CommandRunner.ExecuteAsync(new FirewallCommand("nft", ["-a", "list", "chain", "inet", "ipban", "input"]),
            CommandTimeout, cancellationToken);

    private static bool IsMissingChain(FirewallCommandResult result) =>
        !result.WasNotFound && !result.WasPermissionDenied && !result.WasTimedOut
        && result.StandardError.Contains("No such file or directory", StringComparison.OrdinalIgnoreCase);

    private async Task<(FirewallStatus Status, string ErrorCode, string ErrorMessage)?> EnsureTableAndChainAsync(
        CancellationToken cancellationToken)
    {
        var tableProbe = await CommandRunner.ExecuteAsync(
            new FirewallCommand("nft", ["list", "table", "inet", "ipban"]),
            CommandTimeout,
            cancellationToken).ConfigureAwait(false);
        if (!tableProbe.Succeeded)
        {
            var tableCreate = await CommandRunner.ExecuteAsync(
                new FirewallCommand("nft", ["add", "table", "inet", "ipban"]),
                CommandTimeout,
                cancellationToken).ConfigureAwait(false);
            if (!tableCreate.Succeeded)
            {
                return Failure(tableCreate, "FIREWALL_NFT_TABLE_FAILED");
            }
        }

        var chainProbe = await CommandRunner.ExecuteAsync(
            new FirewallCommand("nft", ["list", "chain", "inet", "ipban", "input"]),
            CommandTimeout,
            cancellationToken).ConfigureAwait(false);
        if (!chainProbe.Succeeded)
        {
            var chainCreate = await CommandRunner.ExecuteAsync(
                new FirewallCommand(
                    "nft",
                    ["add", "chain", "inet", "ipban", "input", "{ type filter hook input priority 0; policy accept; }"]),
                CommandTimeout,
                cancellationToken).ConfigureAwait(false);
            if (!chainCreate.Succeeded)
            {
                return Failure(chainCreate, "FIREWALL_NFT_CHAIN_FAILED");
            }
        }

        return null;
    }

    private static (FirewallStatus Status, string ErrorCode, string ErrorMessage) Failure(
        FirewallCommandResult result,
        string errorCode)
    {
        var status = result.WasNotFound
            ? FirewallStatus.Unsupported
            : result.WasPermissionDenied
                ? FirewallStatus.PermissionDenied
                : result.WasTimedOut
                    ? FirewallStatus.CommandFailed
                    : FirewallStatus.CommandFailed;
        var message = string.IsNullOrWhiteSpace(result.StandardError)
            ? "nftables 命令执行失败。"
            : result.StandardError.Trim();
        return (status, errorCode, message.Length <= 512 ? message : message[..512]);
    }

    private static string[] ParseRuleHandles(string output, string normalizedAddress)
    {
        var addressKind = FirewallAddressValidator.IsIpv6(normalizedAddress) ? "ip6" : "ip";
        var pattern = $@"^[ \t]*{addressKind}\s+saddr\s+(?<address>\S+)\s+drop\s+#\s+handle\s+(?<handle>\d+)\b";
        return Regex.Matches(output, pattern, RegexOptions.CultureInvariant | RegexOptions.IgnoreCase | RegexOptions.Multiline)
            .Where(match => FirewallAddressValidator.TryNormalize(match.Groups["address"].Value, out var address)
                && string.Equals(address, normalizedAddress, StringComparison.Ordinal))
            .Select(match => match.Groups["handle"].Value)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    private FirewallActionResult FailureResult(
        string normalizedAddress,
        FirewallStatus status,
        string errorCode,
        string? errorMessage) => new(
        Name,
        normalizedAddress,
        FirewallActionStatus.Failed,
        status,
        errorCode,
        errorMessage,
        DateTimeOffset.UtcNow);

    private FirewallActionResult RemovedResult(string normalizedAddress) => new(
        Name,
        normalizedAddress,
        FirewallActionStatus.Removed,
        FirewallStatus.Enabled,
        null,
        null,
        DateTimeOffset.UtcNow);

    // 保留基类抽象合同；实际解封由上面的句柄查询逻辑执行。
    protected override FirewallCommand CreateUnbanCommand(string normalizedAddress) =>
        new("nft", ["delete", "rule", "inet", "ipban", "input", "handle", "0"]);
}
