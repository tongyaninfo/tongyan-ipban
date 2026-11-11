namespace IpBan.Agent.Service;

/// <summary>
/// 结构化宿主命令。Provider 只能传入可校验的参数列表，禁止拼接 shell 命令。
/// </summary>
public sealed record FirewallCommand(string FileName, IReadOnlyList<string> Arguments);

public sealed record FirewallCommandResult(
    int ExitCode,
    string StandardOutput,
    string StandardError,
    bool WasNotFound = false,
    bool WasPermissionDenied = false,
    bool WasTimedOut = false)
{
    public bool Succeeded => !WasNotFound
        && !WasPermissionDenied
        && !WasTimedOut
        && ExitCode == 0;
}

public interface IFirewallCommandRunner
{
    Task<FirewallCommandResult> ExecuteAsync(
        FirewallCommand command,
        TimeSpan timeout,
        CancellationToken cancellationToken = default);
}
