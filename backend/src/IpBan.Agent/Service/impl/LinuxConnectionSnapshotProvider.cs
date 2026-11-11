using System.Globalization;
using System.Net;
using IpBan.Agent.Service;
using IpBan.Shared.Models;

namespace IpBan.Agent.Service.impl;

/// <summary>
/// 通过 Linux ss 的结构化输出读取当前 TCP 连接。
/// </summary>
public sealed class LinuxConnectionSnapshotProvider(
    IFirewallCommandRunner commandRunner) : IConnectionSnapshotProvider
{
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(15);

    public async Task<IReadOnlyList<ConnectionSnapshotContract>> QueryAsync(
        CancellationToken cancellationToken = default)
    {
        var result = await commandRunner.ExecuteAsync(
            new FirewallCommand("ss", ["-tnpH"]),
            CommandTimeout,
            cancellationToken).ConfigureAwait(false);

        if (!result.Succeeded)
        {
            throw new InvalidOperationException(DescribeFailure(result));
        }

        return Parse(result.StandardOutput, DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// 解析 ss -tnpH 输出。解析失败的远端端点会被丢弃，绝不填充 Unknown。
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
            if (fields.Length < 5)
            {
                continue;
            }

            if (!TryParseEndpoint(fields[4], requireAddress: true, out var remoteIp, out var remotePort)
                || remoteIp is null)
            {
                continue;
            }

            TryParseEndpoint(fields[3], requireAddress: false, out var localIp, out var localPort);
            var processInfo = fields.Length > 5
                ? string.Join(' ', fields.Skip(5))
                : string.Empty;
            ParseProcessInfo(processInfo, out var processName, out var processId);

            snapshots.Add(new ConnectionSnapshotContract(
                Protocol: "tcp",
                State: fields[0],
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
        bool requireAddress,
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
            var closingBracket = value.IndexOf("]:" , StringComparison.Ordinal);
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

        if (host != "*" && IPAddress.TryParse(host, out var parsedAddress))
        {
            address = parsedAddress.ToString();
        }
        else if (requireAddress)
        {
            return false;
        }

        if (portText != "*"
            && int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out var parsedPort)
            && parsedPort is >= 0 and <= 65535)
        {
            port = parsedPort;
        }
        else if (portText != "*")
        {
            return false;
        }

        return !requireAddress || address is not null;
    }

    private static void ParseProcessInfo(
        string processInfo,
        out string? processName,
        out int? processId)
    {
        processName = null;
        processId = null;
        const string processPrefix = "users:((\"";
        var start = processInfo.IndexOf(processPrefix, StringComparison.Ordinal);
        if (start < 0)
        {
            return;
        }

        start += processPrefix.Length;
        var end = processInfo.IndexOf('"', start);
        if (end > start)
        {
            processName = processInfo[start..end];
        }

        const string pidPrefix = ",pid=";
        var pidStart = processInfo.IndexOf(pidPrefix, end > start ? end : start, StringComparison.Ordinal);
        if (pidStart >= 0)
        {
            pidStart += pidPrefix.Length;
            var pidEnd = pidStart;
            while (pidEnd < processInfo.Length && char.IsDigit(processInfo[pidEnd]))
            {
                pidEnd++;
            }

            if (int.TryParse(processInfo[pidStart..pidEnd], NumberStyles.None, CultureInfo.InvariantCulture, out var parsedPid))
            {
                processId = parsedPid;
            }
        }
    }

    private static string DescribeFailure(FirewallCommandResult result)
    {
        if (result.WasNotFound)
        {
            return "未找到 ss 命令。";
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
