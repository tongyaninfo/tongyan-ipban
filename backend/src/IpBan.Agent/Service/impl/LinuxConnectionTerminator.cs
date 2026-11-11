using System.Globalization;
using System.Diagnostics;
using System.Net;
using IpBan.Agent.Service;
using IpBan.Shared.Models;

namespace IpBan.Agent.Service.impl;

/// <summary>
/// 使用 ss -K 精确匹配 TCP 四元组断开连接；仅对回环 SSH 连接提供进程级兜底，避免误杀控制 SSH。
/// </summary>
public sealed class LinuxConnectionTerminator(
    IFirewallCommandRunner commandRunner) : IConnectionTerminator
{
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(15);

    public async Task<ConnectionTerminationResult> TerminateAsync(
        IReadOnlyList<ConnectionSnapshotContract> connections,
        CancellationToken cancellationToken = default)
        => await TerminateInternalAsync(connections, allowProcessFallback: false, cancellationToken)
            .ConfigureAwait(false);

    public async Task<ConnectionTerminationResult> TerminateExplicitAsync(
        IReadOnlyList<ConnectionSnapshotContract> connections,
        CancellationToken cancellationToken = default)
        => await TerminateInternalAsync(connections, allowProcessFallback: true, cancellationToken)
            .ConfigureAwait(false);

    public async Task<ConnectionTerminationResult> TerminateExactAsync(ConnectionSnapshotContract connection,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(connection);
        if (!connection.Protocol.Equals("tcp", StringComparison.OrdinalIgnoreCase)
            || !connection.State.Equals("ESTAB", StringComparison.OrdinalIgnoreCase)
            || connection.LocalPort is not (>= 1 and <= 65535) || connection.RemotePort is not (>= 1 and <= 65535)
            || !IPAddress.TryParse(connection.LocalIp, out var localIp) || !IPAddress.TryParse(connection.RemoteIp, out var remoteIp)
            || localIp.Equals(IPAddress.Any) || localIp.Equals(IPAddress.IPv6Any)
            || remoteIp.Equals(IPAddress.Any) || remoteIp.Equals(IPAddress.IPv6Any))
        {
            return new ConnectionTerminationResult(false, 0, 0, "缺少完整 TCP 四元组。");
        }

        // ss 的 src/sport 是本地端点，dst/dport 是对端。精确模式从不发送进程退出命令。
        var command = new FirewallCommand("ss",
        [
            "-K", "-t", "state", "established",
            "src", localIp.ToString(), "sport", "=", connection.LocalPort.Value.ToString(CultureInfo.InvariantCulture),
            "dst", remoteIp.ToString(), "dport", "=", connection.RemotePort.Value.ToString(CultureInfo.InvariantCulture)
        ]);
        var result = await commandRunner.ExecuteAsync(command, CommandTimeout, cancellationToken).ConfigureAwait(false);
        return result.Succeeded
            ? new ConnectionTerminationResult(true, 1, 1, null)
            : new ConnectionTerminationResult(false, 1, 0, "精确下线命令执行失败。");
    }

    private async Task<ConnectionTerminationResult> TerminateInternalAsync(
        IReadOnlyList<ConnectionSnapshotContract> connections,
        bool allowProcessFallback,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connections);

        var candidates = connections
            .Where(connection => connection.Protocol.Equals("tcp", StringComparison.OrdinalIgnoreCase)
                && connection.RemotePort is not null
                && connection.LocalPort is not null
                && !string.IsNullOrWhiteSpace(connection.RemoteIp))
            .GroupBy(ConnectionPairKey, StringComparer.Ordinal)
            .Select(group => group
                .OrderByDescending(IsLikelyServerSide)
                .ThenBy(connection => connection.LocalPort)
                .First())
            .ToArray();
        if (candidates.Length == 0)
        {
            return new ConnectionTerminationResult(true, 0, 0, null);
        }

        var terminated = 0;
        var errors = new List<string>();
        foreach (var connection in candidates)
        {
            string? processError = null;
            var command = new FirewallCommand(
                "ss",
                [
                    "-K",
                    "dst", connection.RemoteIp,
                    "sport", "=", connection.RemotePort!.Value.ToString(CultureInfo.InvariantCulture),
                    "dport", "=", connection.LocalPort!.Value.ToString(CultureInfo.InvariantCulture)
                ]);
            var result = await commandRunner.ExecuteAsync(command, CommandTimeout, cancellationToken)
                .ConfigureAwait(false);
            if (result.Succeeded
                && TryTerminateOwningProcess(connection, allowProcessFallback, out processError))
            {
                terminated++;
                continue;
            }

            var detail = result.WasNotFound
                ? "未找到 ss 命令。"
                : result.WasPermissionDenied
                    ? "断开连接权限不足。"
                    : result.WasTimedOut
                        ? "断开连接超时。"
                        : (string.IsNullOrWhiteSpace(result.StandardError)
                            ? result.StandardOutput
                            : result.StandardError);
            detail = detail.ReplaceLineEndings(" ").Trim();
            if (detail.Length > 256)
            {
                detail = detail[..256];
            }

            if (!result.Succeeded && detail.Length == 0)
            {
                detail = "ss -K 执行失败。";
            }

            if (result.Succeeded && !string.IsNullOrWhiteSpace(processError))
            {
                detail = processError;
            }

            errors.Add(detail);
        }

        return new ConnectionTerminationResult(
            Success: terminated == candidates.Length,
            Attempted: candidates.Length,
            Terminated: terminated,
            Error: errors.Count == 0 ? null : string.Join("; ", errors));
    }

    private static string ConnectionPairKey(ConnectionSnapshotContract connection)
    {
        var local = $"{connection.LocalIp}:{connection.LocalPort}";
        var remote = $"{connection.RemoteIp}:{connection.RemotePort}";
        return string.CompareOrdinal(local, remote) <= 0
            ? $"{local}|{remote}"
            : $"{remote}|{local}";
    }

    private static int IsLikelyServerSide(ConnectionSnapshotContract connection)
    {
        if (connection.ProcessName?.Contains("sshd", StringComparison.OrdinalIgnoreCase) == true)
        {
            return 2;
        }

        // 服务端通常绑定低端口；同一回环连接同时呈现两侧时优先服务端一侧。
        return connection.LocalPort is <= 1024 ? 1 : 0;
    }

    /// <summary>
    /// 某些发行版内核会让 ss -K 返回成功但不真正销毁 socket。回环 SSH 没有远端控制主机，
    /// 因此允许结束本次快照明确关联的 ssh/sshd 进程；非回环连接只依赖 ss -K，失败时明确返回错误，
    /// 不通过 PID 猜测或进程树结束控制 SSH。
    /// </summary>
    private static bool TryTerminateOwningProcess(
        ConnectionSnapshotContract connection,
        bool allowProcessFallback,
        out string? error)
    {
        error = null;
        if (!allowProcessFallback && !IsLoopback(connection.RemoteIp))
        {
            return true;
        }

        if (connection.ProcessId is not { } processId
            || string.IsNullOrWhiteSpace(connection.ProcessName)
            || (!connection.ProcessName.Contains("ssh", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        try
        {
            using var process = Process.GetProcessById(processId);
            if (process.HasExited)
            {
                return true;
            }

            if (!process.ProcessName.Contains("ssh", StringComparison.OrdinalIgnoreCase))
            {
                // PID 已被复用；不能仅凭旧快照进程名结束无关进程。
                return true;
            }

            process.Kill(entireProcessTree: true);
            process.WaitForExit(1000);
            return true;
        }
        catch (ArgumentException)
        {
            // 连接已经在 ss -K 或对端主动关闭后退出。
            return true;
        }
        catch (InvalidOperationException)
        {
            return true;
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or UnauthorizedAccessException or AggregateException)
        {
            error = $"无法结束 SSH 关联进程 {processId}: {exception.Message}";
            return false;
        }
    }

    private static bool IsLoopback(string? address) =>
        address is "127.0.0.1" or "::1";
}
