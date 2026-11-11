using System.Globalization;
using System.ComponentModel;
using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;
using IpBan.Agent.Service;
using IpBan.Shared.Models;

namespace IpBan.Agent.Service.impl;

/// <summary>
/// 优先使用 Remove-NetTCPConnection 按四元组断开 Windows TCP 连接。
/// Windows Server 2019 的部分安装不带该 cmdlet，因此对明确关联的 WinRM 子进程提供受限兜底；
/// 不结束 sshd、svchost 或 TermService，避免把服务和其他会话一起误杀。
/// </summary>
public sealed class WindowsConnectionTerminator(
    IFirewallCommandRunner commandRunner) : IConnectionTerminator
{
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(15);

    public Task<ConnectionTerminationResult> TerminateAsync(
        IReadOnlyList<ConnectionSnapshotContract> connections,
        CancellationToken cancellationToken = default) =>
        TerminateInternalAsync(connections, allowProcessFallback: true, cancellationToken);

    public Task<ConnectionTerminationResult> TerminateExplicitAsync(
        IReadOnlyList<ConnectionSnapshotContract> connections,
        CancellationToken cancellationToken = default) =>
        TerminateInternalAsync(connections, allowProcessFallback: true, cancellationToken);

    public Task<ConnectionTerminationResult> TerminateExactAsync(ConnectionSnapshotContract connection,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(connection);
        if (!IPAddress.TryParse(connection.LocalIp, out var localIp) || !IPAddress.TryParse(connection.RemoteIp, out var remoteIp)
            || localIp.Equals(IPAddress.Any) || localIp.Equals(IPAddress.IPv6Any)
            || remoteIp.Equals(IPAddress.Any) || remoteIp.Equals(IPAddress.IPv6Any))
            return Task.FromResult(new ConnectionTerminationResult(false, 0, 0, "缺少完整 TCP 四元组。"));
        return TerminateInternalAsync([connection], allowProcessFallback: false, cancellationToken);
    }

    private async Task<ConnectionTerminationResult> TerminateInternalAsync(
        IReadOnlyList<ConnectionSnapshotContract> connections,
        bool allowProcessFallback,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connections);

        var candidates = connections
            .Where(connection => connection.Protocol.Equals("tcp", StringComparison.OrdinalIgnoreCase)
                && connection.State.Equals("ESTAB", StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(connection.RemoteIp)
                && connection.RemotePort is >= 1 and <= 65535
                && !string.IsNullOrWhiteSpace(connection.LocalIp)
                && connection.LocalPort is >= 1 and <= 65535)
            .GroupBy(ConnectionKey, StringComparer.Ordinal)
            .Select(group => group.First())
            .ToArray();

        if (candidates.Length == 0)
        {
            return new ConnectionTerminationResult(allowProcessFallback, 0, 0,
                allowProcessFallback ? null : "缺少完整 TCP 四元组。");
        }

        var terminated = 0;
        var errors = new List<string>();
        foreach (var connection in candidates)
        {
            // Windows Server 2019 可能没有 NetTCPIP.Remove-NetTCPConnection；
            // SetTcpEntry 是系统提供的精确 TCB 删除入口，按四元组直接下线 IPv4 连接。
            if (TryDeleteTcpEntry(connection, out var tcpEntryError))
            {
                terminated++;
                continue;
            }

            var command = new FirewallCommand(
                "powershell.exe",
                [
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    BuildRemovalScript(connection, allowProcessFallback)
                ]);
            var result = await commandRunner.ExecuteAsync(command, CommandTimeout, cancellationToken)
                .ConfigureAwait(false);
            if (result.Succeeded)
            {
                terminated++;
                continue;
            }

            var detail = DescribeFailure(result);
            if (!string.IsNullOrWhiteSpace(tcpEntryError))
            {
                detail = $"{tcpEntryError}；{detail}";
            }

            errors.Add(detail);
        }

        return new ConnectionTerminationResult(
            Success: terminated == candidates.Length,
            Attempted: candidates.Length,
            Terminated: terminated,
            Error: errors.Count == 0 ? null : string.Join("; ", errors));
    }

    private static string BuildRemovalScript(ConnectionSnapshotContract connection, bool allowProcessFallback)
    {
        var localAddress = EscapePowerShellString(connection.LocalIp!);
        var remoteAddress = EscapePowerShellString(connection.RemoteIp);
        var localPort = connection.LocalPort!.Value.ToString(CultureInfo.InvariantCulture);
        var remotePort = connection.RemotePort!.Value.ToString(CultureInfo.InvariantCulture);
        var processId = connection.ProcessId?.ToString(CultureInfo.InvariantCulture) ?? "0";

        // 先精确查找，再删除；找不到连接返回非零状态，避免把“快照已过期”误报为成功。
        // fallback 只允许结束当前快照所属的 WinRM 子进程，绝不结束 sshd、svchost 或 TermService。
        var removeSocket = $"$c=Get-NetTCPConnection -LocalAddress '{localAddress}' -LocalPort {localPort} -RemoteAddress '{remoteAddress}' -RemotePort {remotePort} -State Established -ErrorAction SilentlyContinue; if ($null -eq $c) {{ exit 2 }}; if (Get-Command Remove-NetTCPConnection -ErrorAction SilentlyContinue) {{ $c | Remove-NetTCPConnection -Confirm:$false -ErrorAction Stop; exit 0 }}; ";
        var terminateWinRmProcess = allowProcessFallback
            ? $"$p=Get-Process -Id {processId} -ErrorAction SilentlyContinue; if ($null -ne $p -and @('wsmprovhost','winrshost') -contains $p.ProcessName.ToLowerInvariant()) {{ Stop-Process -Id {processId} -Force -ErrorAction Stop; exit 0 }}; "
            : string.Empty;
        return removeSocket + terminateWinRmProcess + "exit 3";
    }

    private static string EscapePowerShellString(string value) => value.Replace("'", "''", StringComparison.Ordinal);

    private static bool TryDeleteTcpEntry(
        ConnectionSnapshotContract connection,
        out string? error)
    {
        error = null;
        if (!IPAddress.TryParse(connection.LocalIp, out var localIp)
            || !IPAddress.TryParse(connection.RemoteIp, out var remoteIp)
            || localIp.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork
            || remoteIp.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork
            || connection.LocalPort is not { } localPort
            || connection.RemotePort is not { } remotePort)
        {
            return false;
        }

        var row = new MibTcpRow
        {
            State = TcpStateDeleteTcb,
            LocalAddress = BitConverter.ToUInt32(localIp.GetAddressBytes(), 0),
            LocalPort = EncodeNetworkPort(localPort),
            RemoteAddress = BitConverter.ToUInt32(remoteIp.GetAddressBytes(), 0),
            RemotePort = EncodeNetworkPort(remotePort)
        };

        try
        {
            var result = SetTcpEntry(ref row);
            if (result == 0)
            {
                return true;
            }

            error = $"SetTcpEntry 返回错误 {result}：{new Win32Exception((int)result).Message}";
            return false;
        }
        catch (DllNotFoundException)
        {
            // 非 Windows 或裁剪环境回退到命令实现。
            return false;
        }
        catch (EntryPointNotFoundException)
        {
            return false;
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or Win32Exception)
        {
            error = $"SetTcpEntry 执行失败：{exception.Message}";
            return false;
        }
    }

    private static uint EncodeNetworkPort(int port)
    {
        // MIB_TCPROW 的 DWORD 端口字段保存 htons 后的低 16 位。
        // 例如 22 应编码为 0x1600，而不是把网络字节放到 DWORD 的高 16 位。
        return BinaryPrimitives.ReverseEndianness((ushort)port);
    }

    private const uint TcpStateDeleteTcb = 12;

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRow
    {
        public uint State;
        public uint LocalAddress;
        public uint LocalPort;
        public uint RemoteAddress;
        public uint RemotePort;
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint SetTcpEntry(ref MibTcpRow row);

    private static string ConnectionKey(ConnectionSnapshotContract connection) =>
        $"{connection.LocalIp}:{connection.LocalPort}|{connection.RemoteIp}:{connection.RemotePort}";

    private static string DescribeFailure(FirewallCommandResult result)
    {
        if (result.WasNotFound)
        {
            return "未找到 powershell.exe，无法断开 Windows 连接。";
        }

        if (result.WasPermissionDenied)
        {
            return "断开 Windows 连接权限不足。";
        }

        if (result.WasTimedOut)
        {
            return "断开 Windows 连接超时。";
        }

        var detail = string.IsNullOrWhiteSpace(result.StandardError)
            ? result.StandardOutput
            : result.StandardError;
        detail = detail.ReplaceLineEndings(" ").Trim();
        if (result.ExitCode == 2 && detail.Length == 0)
        {
            detail = "连接已不存在或快照已过期。";
        }

        if (result.ExitCode == 3 && detail.Length == 0)
        {
            detail = "当前 Windows 版本未提供 TCP 精确断开命令，且该连接不允许使用进程级兜底。";
        }

        if (detail.Length == 0)
        {
            detail = "Remove-NetTCPConnection 执行失败。";
        }

        return detail.Length > 256 ? detail[..256] : detail;
    }
}
