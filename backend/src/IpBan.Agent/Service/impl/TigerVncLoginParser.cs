using System.Globalization;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using IpBan.Shared.Models;

namespace IpBan.Agent.Service.impl;

/// <summary>
/// 每个日志流独立关联 TigerVNC 的连接及认证结果。匿名成功消息只关联唯一、未发生交错的连接。
/// </summary>
internal sealed partial class TigerVncLoginParser
{
    private readonly Dictionary<string, PendingConnection> pending = new(StringComparer.Ordinal);
    private DateTimeOffset? nativeTimestamp;
    private string? localIp;
    private int? localPort;
    private string processName = "Xvnc";
    private bool correlationOverloaded;
    private bool hasCompleteContext;

    public RawLoginEventInput? Parse(string line, string source, string recordId,
        DateTimeOffset? journalTimestamp = null, int? processId = null, string? commandName = null)
    {
        var message = line.Trim();
        if (TryReadTimestamp(message, out var timestamp))
        {
            nativeTimestamp = timestamp;
            return null;
        }

        if (message.StartsWith("Xtigervnc TigerVNC", StringComparison.Ordinal))
        {
            processName = "Xtigervnc";
        }
        if (commandName is "Xvnc" or "Xtigervnc")
        {
            processName = commandName;
        }

        var occurred = journalTimestamp ?? nativeTimestamp;
        ReadListener(message);
        var accepted = AcceptedRegex().Match(message);
        if (accepted.Success && TryReadEndpoint(accepted.Groups[1].Value, out var address, out var port))
        {
            // 并行握手没有连接 ID 的成功日志不能靠“最后一条 accepted”猜测来源。
            if (pending.Count > 0)
            {
                foreach (var candidate in pending.Values)
                {
                    candidate.Ambiguous = true;
                }
            }
            if (pending.Count >= 1024)
            {
                // 超量时保留歧义状态；清空后只记新连接会伪造“唯一来源”。
                correlationOverloaded = true;
                return null;
            }
            pending[accepted.Groups[1].Value] = new(address, port, pending.Count > 0, occurred);
            return null;
        }

        var closing = ClosingRegex().Match(message);
        if (closing.Success)
        {
            var endpoint = closing.Groups[1].Value;
            pending.Remove(endpoint);
            // 协议探测、断开、黑名单拒绝都不是一次新的密码失败。
            if (!closing.Groups[2].Value.Contains("Authentication failure", StringComparison.OrdinalIgnoreCase)
                || occurred is null || !TryReadEndpoint(endpoint, out address, out port))
            {
                return null;
            }
            return Create(false, address, port, occurred.Value, source, recordId, processId);
        }

        // TigerVNC 1.13 的 VNCSConnectionST::authSuccess 每次认证成功均写出此行。
        // starting desktop 仅代表共享桌面启动，不能作为每次登录的证据。
        if (!message.StartsWith("VNCSConnST:", StringComparison.Ordinal)
            || !message.Contains("Server default pixel format", StringComparison.Ordinal)
            || occurred is null)
        {
            return null;
        }

        PendingConnection? connection = null;
        if (hasCompleteContext && !correlationOverloaded && pending.Count == 1)
        {
            var candidate = pending.First();
            if (!candidate.Value.Ambiguous && candidate.Value.AcceptedAt is { } acceptedAt
                && occurred.Value - acceptedAt <= TimeSpan.FromMinutes(5))
            {
                connection = candidate.Value;
                pending.Remove(candidate.Key);
            }
        }
        return Create(true, connection?.Address, connection?.Port, occurred.Value, source, recordId, processId);
    }

    private RawLoginEventInput Create(bool success, string? address, int? port, DateTimeOffset timestamp,
        string source, string recordId, int? processId) => new(
        timestamp, ProtocolKind.Vnc, success, null, address, port, localIp, localPort,
        processId, processName, null, null, "linux-tigervnc", $"{recordId}:{timestamp.UtcTicks}", source,
        address is null ? FieldAvailability.CorrelationFailed : FieldAvailability.Available,
        port is null ? FieldAvailability.CorrelationFailed : FieldAvailability.Available,
        localIp is not null && localPort is not null ? FieldAvailability.Available : FieldAvailability.NotCollected,
        FieldAvailability.NotProvided, FieldAvailability.Available);

    private void ReadListener(string message)
    {
        var listener = ListenerRegex().Match(message);
        if (listener.Success)
        {
            // 从日志尾部开始读取时，可能存在尚未被观测的握手。
            // 只有见到服务监听启动标记，才允许用唯一握手关联匿名成功消息。
            hasCompleteContext = true;
            var addressText = listener.Groups[1].Value.Trim();
            localIp = IPAddress.TryParse(addressText, out var address)
                && !address.Equals(IPAddress.Any) && !address.Equals(IPAddress.IPv6Any) ? address.ToString() : null;
            var portMatch = PortRegex().Match(message);
            localPort = ReadPort(portMatch.Groups[1].Value);
        }
        else if (message.StartsWith("port ", StringComparison.Ordinal))
        {
            localPort = ReadPort(PortRegex().Match(message).Groups[1].Value);
        }
    }

    internal static bool TryReadEndpoint(string value, [NotNullWhen(true)] out string? address, out int? port)
    {
        address = null;
        port = null;
        // TigerVNC 的 IPv4/IPv6 均使用 address::port，按最后一个双冒号拆分。
        var separator = value.LastIndexOf("::", StringComparison.Ordinal);
        if (separator <= 0 || !IPAddress.TryParse(value[..separator].Trim('[', ']'), out var parsed))
        {
            return false;
        }
        port = ReadPort(value[(separator + 2)..]);
        if (port is null)
        {
            return false;
        }
        address = parsed.IsIPv4MappedToIPv6 ? parsed.MapToIPv4().ToString() : parsed.ToString();
        return true;
    }

    internal static bool TryReadTimestamp(string message, out DateTimeOffset timestamp)
    {
        // TigerVNC 文件日期使用主机本地时区；持久化统一转为 UTC。
        var normalized = string.Join(' ', message.Split(' ', StringSplitOptions.RemoveEmptyEntries));
        if (DateTime.TryParseExact(normalized, "ddd MMM d HH:mm:ss yyyy", CultureInfo.InvariantCulture,
            DateTimeStyles.AllowWhiteSpaces, out var local))
        {
            timestamp = new DateTimeOffset(DateTime.SpecifyKind(local, DateTimeKind.Local)).ToUniversalTime();
            return true;
        }
        timestamp = default;
        return false;
    }

    internal static string StableId(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static int? ReadPort(string value) => int.TryParse(value, CultureInfo.InvariantCulture, out var port)
        && port is > 0 and <= 65535 ? port : null;

    [GeneratedRegex(@"^Connections:\s+accepted:\s+(.+?)\s*$", RegexOptions.CultureInvariant)]
    private static partial Regex AcceptedRegex();
    [GeneratedRegex(@"^VNCSConnST:\s+closing (.+?): (.+)$", RegexOptions.CultureInvariant)]
    private static partial Regex ClosingRegex();
    [GeneratedRegex(@"Listening for VNC connections on (.+?) interface\(s\)", RegexOptions.CultureInvariant)]
    private static partial Regex ListenerRegex();
    [GeneratedRegex(@"\bport (\d{1,5})\b", RegexOptions.CultureInvariant)]
    private static partial Regex PortRegex();

    private sealed class PendingConnection(string address, int? port, bool ambiguous, DateTimeOffset? acceptedAt)
    {
        public string Address { get; } = address;
        public int? Port { get; } = port;
        public bool Ambiguous { get; set; } = ambiguous;
        public DateTimeOffset? AcceptedAt { get; } = acceptedAt;
    }
}
