using System.Security.Cryptography;
using System.Text;
using IpBan.Shared.Models;

namespace IpBan.Agent.Service.impl;

public abstract class CommandBasedFirewallProvider(
    IFirewallCommandRunner commandRunner) : IFirewallProvider
{
    protected static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(15);

    protected IFirewallCommandRunner CommandRunner { get; } = commandRunner;

    public abstract string Name { get; }

    public abstract string Platform { get; }

    public abstract FirewallCapabilities Capabilities { get; }

    protected abstract FirewallCommand DetectionCommand { get; }

    protected abstract bool IsEnabled(FirewallCommandResult result);

    protected abstract FirewallCommand CreateBanCommand(string normalizedAddress);

    protected abstract FirewallCommand CreateUnbanCommand(string normalizedAddress);

    /// <summary>
    /// 默认每个动作只执行一条命令；需要同时更新运行时和持久化配置的 Provider 可覆盖此方法。
    /// </summary>
    protected virtual IReadOnlyList<FirewallCommand> CreateBanCommands(string normalizedAddress) =>
        [CreateBanCommand(normalizedAddress)];

    protected virtual IReadOnlyList<FirewallCommand> CreateUnbanCommands(string normalizedAddress) =>
        [CreateUnbanCommand(normalizedAddress)];

    public async Task<FirewallObservation> DetectAsync(CancellationToken cancellationToken = default)
    {
        var result = await ExecuteAsync(DetectionCommand, cancellationToken).ConfigureAwait(false);
        var status = ResolveDetectionStatus(result, IsEnabled(result));
        return new FirewallObservation(
            Name,
            status,
            status == FirewallStatus.Enabled,
            Describe(result),
            DateTimeOffset.UtcNow,
            Capabilities);
    }

    public virtual Task<FirewallActionResult> BanAsync(
        string sourceAddress,
        CancellationToken cancellationToken = default) => ExecuteActionAsync(
        sourceAddress,
        FirewallActionStatus.Applied,
        CreateBanCommands,
        cancellationToken);

    public virtual Task<FirewallActionResult> UnbanAsync(
        string sourceAddress,
        CancellationToken cancellationToken = default) => ExecuteActionAsync(
        sourceAddress,
        FirewallActionStatus.Removed,
        CreateUnbanCommands,
        cancellationToken);

    protected static string RuleName(string normalizedAddress)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(normalizedAddress));
        return $"IPBan-{Convert.ToHexString(digest)[..16]}";
    }

    private async Task<FirewallActionResult> ExecuteActionAsync(
        string sourceAddress,
        FirewallActionStatus successStatus,
        Func<string, IReadOnlyList<FirewallCommand>> commandFactory,
        CancellationToken cancellationToken)
    {
        if (!FirewallAddressValidator.TryNormalize(sourceAddress, out var normalizedAddress))
        {
            return Failure(
                sourceAddress,
                FirewallActionStatus.Failed,
                FirewallStatus.CommandFailed,
                "FIREWALL_INVALID_SOURCE",
                "来源地址必须是合法 IP 或 CIDR。 ");
        }

        var observation = await DetectAsync(cancellationToken).ConfigureAwait(false);
        if (observation.Status != FirewallStatus.Enabled)
        {
            var actionStatus = observation.Status == FirewallStatus.Disabled
                ? FirewallActionStatus.Disabled
                : FirewallActionStatus.Failed;
            return Failure(
                normalizedAddress,
                actionStatus,
                observation.Status,
                $"FIREWALL_{observation.Status.ToString().ToUpperInvariant()}",
                observation.Detail);
        }

        var commands = commandFactory(normalizedAddress);
        foreach (var command in commands)
        {
            var result = await ExecuteAsync(command, cancellationToken).ConfigureAwait(false);
            if (result.Succeeded)
            {
                continue;
            }

            var status = ResolveDetectionStatus(result, enabled: false);
            return Failure(
                normalizedAddress,
                FirewallActionStatus.Failed,
                status,
                $"FIREWALL_{status.ToString().ToUpperInvariant()}",
                Describe(result));
        }

        if (commands.Count > 0)
        {
            return new FirewallActionResult(
                Name,
                normalizedAddress,
                successStatus,
                FirewallStatus.Enabled,
                null,
                null,
                DateTimeOffset.UtcNow);
        }

        return Failure(
            normalizedAddress,
            FirewallActionStatus.Failed,
            FirewallStatus.CommandFailed,
            "FIREWALL_COMMAND_FAILED",
            "Provider 未返回任何防火墙命令。");
    }

    private async Task<FirewallCommandResult> ExecuteAsync(
        FirewallCommand command,
        CancellationToken cancellationToken) => await CommandRunner.ExecuteAsync(
        command,
        CommandTimeout,
        cancellationToken).ConfigureAwait(false);

    private FirewallActionResult Failure(
        string sourceAddress,
        FirewallActionStatus actionStatus,
        FirewallStatus status,
        string errorCode,
        string? errorMessage) => new(
        Name,
        sourceAddress,
        actionStatus,
        status,
        errorCode,
        Sanitize(errorMessage),
        DateTimeOffset.UtcNow);

    private static FirewallStatus ResolveDetectionStatus(FirewallCommandResult result, bool enabled)
    {
        if (result.WasNotFound)
        {
            return FirewallStatus.Unsupported;
        }

        if (result.WasPermissionDenied)
        {
            return FirewallStatus.PermissionDenied;
        }

        if (result.WasTimedOut || !result.Succeeded && !enabled)
        {
            return FirewallStatus.CommandFailed;
        }

        return enabled ? FirewallStatus.Enabled : FirewallStatus.Disabled;
    }

    private static string? Describe(FirewallCommandResult result)
    {
        if (result.WasNotFound)
        {
            return "未找到防火墙命令。";
        }

        if (result.WasPermissionDenied)
        {
            return "权限不足。";
        }

        if (result.WasTimedOut)
        {
            return "防火墙命令超时。";
        }

        return Sanitize(string.IsNullOrWhiteSpace(result.StandardError)
            ? result.StandardOutput
            : result.StandardError);
    }

    private static string? Sanitize(string? message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return null;
        }

        var singleLine = message.ReplaceLineEndings(" ").Trim();
        return singleLine.Length <= 512 ? singleLine : singleLine[..512];
    }
}
