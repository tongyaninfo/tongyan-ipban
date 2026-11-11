using System.Diagnostics;
using System.ComponentModel;

namespace IpBan.Agent.Service.impl;

/// <summary>
/// 使用 ProcessStartInfo.ArgumentList 启动命令，避免经过 shell 解析。
/// </summary>
public sealed class ProcessFirewallCommandRunner : IFirewallCommandRunner
{
    public async Task<FirewallCommandResult> ExecuteAsync(
        FirewallCommand command,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentException.ThrowIfNullOrWhiteSpace(command.FileName);

        var startInfo = new ProcessStartInfo
        {
            FileName = command.FileName,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        foreach (var argument in command.Arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = startInfo };
        try
        {
            if (!process.Start())
            {
                return new FirewallCommandResult(-1, string.Empty, "进程未启动。", WasNotFound: true);
            }

            var standardOutputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var standardErrorTask = process.StandardError.ReadToEndAsync(cancellationToken);
            using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutSource.CancelAfter(timeout);

            try
            {
                await process.WaitForExitAsync(timeoutSource.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                TryKill(process);
                return new FirewallCommandResult(
                    -1,
                    await standardOutputTask.ConfigureAwait(false),
                    await standardErrorTask.ConfigureAwait(false),
                    WasTimedOut: true);
            }

            return new FirewallCommandResult(
                process.ExitCode,
                await standardOutputTask.ConfigureAwait(false),
                await standardErrorTask.ConfigureAwait(false));
        }
        catch (FileNotFoundException)
        {
            return new FirewallCommandResult(-1, string.Empty, "命令不存在。", WasNotFound: true);
        }
        catch (Win32Exception exception) when (exception.NativeErrorCode == 2)
        {
            // Linux 上 Process.Start 对不存在的命令通常抛 Win32Exception，而不是 FileNotFoundException。
            // Provider 探测必须把它识别为 Unsupported，不能让 Agent 因缺少 ufw/nftables 命令而退出。
            return new FirewallCommandResult(-1, string.Empty, "命令不存在。", WasNotFound: true);
        }
        catch (UnauthorizedAccessException)
        {
            return new FirewallCommandResult(-1, string.Empty, "权限不足。", WasPermissionDenied: true);
        }
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (InvalidOperationException)
        {
            // 进程可能已经退出，忽略竞态。
        }
    }
}
