using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using IpBan.Shared.Models;

namespace IpBan.Agent.Service.impl;

/// <summary>
/// 解析 sshd 的 Accepted/Failed 日志。它只处理文本，不执行命令，便于合成日志回放测试。
/// </summary>
internal static partial class LinuxSshLoginParser
{
    public static bool TryParse(
        string message,
        DateTimeOffset occurredAtUtc,
        string? rawEventId,
        int? localProcessId,
        out RawLoginEventInput input)
    {
        input = default!;
        if (string.IsNullOrWhiteSpace(message))
        {
            return false;
        }

        var result = AuthenticationResultPattern().Match(message);
        if (!result.Success)
        {
            return false;
        }

        var endpoint = EndpointPattern().Match(message, result.Length);
        if (!endpoint.Success)
        {
            return false;
        }

        // sshd 会输出客户端提供的用户名和证书说明。端点有歧义时保留认证结果，来源标为无法关联。
        var unambiguous = endpoint.Index == result.Length && !endpoint.NextMatch().Success;
        string? remoteIp = null;
        int? remotePort = null;
        if (unambiguous
            && IPAddress.TryParse(endpoint.Groups["ip"].Value, out var remoteAddress)
            && int.TryParse(endpoint.Groups["port"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var port)
            && port is >= 1 and <= 65535)
        {
            remoteIp = remoteAddress.ToString();
            remotePort = port;
        }

        var username = unambiguous ? result.Groups["user"].Value : null;

        input = new RawLoginEventInput(
            OccurredAtUtc: occurredAtUtc.ToUniversalTime(),
            Protocol: ProtocolKind.Ssh,
            Success: result.Groups["accepted"].Success,
            Username: username,
            RemoteIp: remoteIp,
            RemotePort: remotePort,
            LocalIp: null,
            LocalPort: null,
            LocalProcessId: localProcessId,
            LocalProcessName: "sshd",
            OriginProcessId: null,
            OriginProcessName: null,
            Collector: "linux-sshd-journald",
            RawEventId: rawEventId,
            EvidenceSource: "journald:sshd",
            RemoteIpAvailability: remoteIp is null ? FieldAvailability.CorrelationFailed : FieldAvailability.Available,
            RemotePortAvailability: remotePort is null ? FieldAvailability.CorrelationFailed : FieldAvailability.Available,
            LocalEndpointAvailability: FieldAvailability.NotCollected,
            UsernameAvailability: username is null ? FieldAvailability.CorrelationFailed : FieldAvailability.Available,
            ProcessAvailability: FieldAvailability.Available);
        return true;
    }

    // Invalid user、PAM 和断开消息只是辅助证据。Failed none 是客户端探测认证方式，不计为凭据失败。
    [GeneratedRegex(
        @"^(?:(?<accepted>Accepted)\s+\S+\s+for|Failed\s+(?!none\s+)\S+\s+for(?:\s+invalid\s+user)?)\s+(?<user>\S+)\s+",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AuthenticationResultPattern();

    [GeneratedRegex(
        @"(?<=\s)from\s+(?<ip>\S+)\s+port\s+(?<port>[0-9]+)\s+ssh2(?=:|\s*$)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex EndpointPattern();
}
