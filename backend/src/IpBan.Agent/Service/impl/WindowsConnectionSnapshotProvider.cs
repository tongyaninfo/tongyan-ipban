using System.Diagnostics;
using System.Globalization;
using System.Net;
using IpBan.Agent.Service;
using IpBan.Shared.Models;

namespace IpBan.Agent.Service.impl;

/// <summary>
/// 使用 Windows netstat 读取当前 TCP 连接，并通过 PID 补齐进程名称。
/// 仅返回可以解析出远端地址、端口和本地端点的记录，避免向管理台写入 Unknown。
/// </summary>
public sealed class WindowsConnectionSnapshotProvider(
    IFirewallCommandRunner commandRunner) : IConnectionSnapshotProvider
{
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(15);

    public async Task<IReadOnlyList<ConnectionSnapshotContract>> QueryAsync(
        CancellationToken cancellationToken = default)
    {
        var result = await commandRunner.ExecuteAsync(
            new FirewallCommand("netstat", ["-ano", "-p", "tcp"]),
            CommandTimeout,
            cancellationToken).ConfigureAwait(false);

        if (!result.Succeeded)
        {
            throw new InvalidOperationException(DescribeFailure(result));
        }

        return Parse(result.StandardOutput, DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// 解析 netstat -ano -p tcp 输出。netstat 的表头和状态受系统语言影响，
    /// 因此只依赖 TCP 行的固定列数，不依赖表头文字。
    /// </summary>
    public static IReadOnlyList<ConnectionSnapshotContract> Parse(
        string output,
        DateTimeOffset observedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(output);

        var snapshots = new List<ConnectionSnapshotContract>();
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var fields = line.Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 5
                || !fields[0].Equals("TCP", StringComparison.OrdinalIgnoreCase)
                || !TryParseEndpoint(fields[1], out var localIp, out var localPort)
                || !TryParseEndpoint(fields[2], out var remoteIp, out var remotePort)
                || remoteIp is null
                || remotePort is null
                || localIp is null
                || localPort is null
                || remotePort == 0
                || !int.TryParse(fields[^1], NumberStyles.None, CultureInfo.InvariantCulture, out var processId)
                || processId <= 0)
            {
                continue;
            }

            // LISTENING 等只有通配远端端点的行已在上面过滤；保留 ESTABLISHED 以及
            // 其它带完整远端端点的状态，便于管理台观察关闭中的连接。
            var processName = TryGetProcessName(processId);
            snapshots.Add(new ConnectionSnapshotContract(
                Protocol: "tcp",
                State: NormalizeState(fields[3]),
                RemoteIp: remoteIp,
                RemotePort: remotePort,
                LocalIp: localIp,
                LocalPort: localPort,
                ProcessId: processId,
                ProcessName: processName,
                ObservedAtUtc: observedAtUtc));
        }

        return snapshots;
    }

    private static bool TryParseEndpoint(
        string value,
        out string? address,
        out int? port)
    {
        address = null;
        port = null;
        value = value.Trim();
        if (value.Length == 0)
        {
            return false;
        }

        string host;
        string portText;
        if (value[0] == '[')
        {
            var closingBracket = value.IndexOf("]:", StringComparison.Ordinal);
            if (closingBracket <= 1)
            {
                return false;
            }

            host = value[1..closingBracket];
            portText = value[(closingBracket + 2)..];
        }
        else
        {
            var separator = value.LastIndexOf(':');
            if (separator <= 0)
            {
                return false;
            }

            host = value[..separator];
            portText = value[(separator + 1)..];
        }

        if (host is "*" or "0.0.0.0" or "::")
        {
            return false;
        }

        // 某些 Windows 版本在 IPv6 地址后附带作用域编号，例如 %12。
        var scopeSeparator = host.IndexOf('%');
        if (scopeSeparator > 0)
        {
            host = host[..scopeSeparator];
        }

        if (!IPAddress.TryParse(host, out var parsedAddress))
        {
            return false;
        }

        if (!int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out var parsedPort)
            || parsedPort is < 0 or > 65535)
        {
            return false;
        }

        address = parsedAddress.ToString();
        port = parsedPort;
        return true;
    }

    private static string NormalizeState(string state) =>
        state.Equals("ESTABLISHED", StringComparison.OrdinalIgnoreCase)
            ? "ESTAB"
            : state;

    private static string? TryGetProcessName(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return process.ProcessName;
        }
        catch (ArgumentException)
        {
            return null;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static string DescribeFailure(FirewallCommandResult result)
    {
        if (result.WasNotFound)
        {
            return "未找到 netstat 命令。";
        }

        if (result.WasPermissionDenied)
        {
            return "读取当前连接权限不足。";
        }

        if (result.WasTimedOut)
        {
            return "读取当前连接超时。";
        }

        var detail = string.IsNullOrWhiteSpace(result.StandardError)
            ? result.StandardOutput
            : result.StandardError;
        detail = detail.ReplaceLineEndings(" ").Trim();
        return detail.Length > 512 ? detail[..512] : detail;
    }
}
