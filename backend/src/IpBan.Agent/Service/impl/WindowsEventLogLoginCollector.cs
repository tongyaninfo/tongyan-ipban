using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using System.Runtime.Versioning;
using IpBan.Shared.Models;
using IpBan.Shared.Logging.Syslog;
using IpBan.Shared.Service;

namespace IpBan.Agent.Service.impl;

/// <summary>
/// Windows 事件日志采集器。OpenSSH 使用自身的认证结果，RDP/WinRM 使用 Security 的认证事件。
/// 会话生命周期及服务内部错误不作为登录结果。
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsEventLogLoginCollector(SyslogRuntime? syslog = null) : ILoginEventCollector
{
    private readonly CollectorLogHealth securityHealth = new(syslog, "Windows 安全日志");
    private readonly CollectorLogHealth sshHealth = new(syslog, "Windows OpenSSH");
    private static readonly string[] Sources =
    [
        WindowsEventLogParser.SecuritySource,
        WindowsEventLogParser.OpenSshSource
    ];

    public string Name => "windows-eventlog";

    public ProtocolKind Protocol => ProtocolKind.Unidentified;

    public Task<IReadOnlyList<RawLoginEventInput>> CollectAsync(
        DateTimeOffset sinceUtc,
        CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult<IReadOnlyList<RawLoginEventInput>>(Array.Empty<RawLoginEventInput>());
        }

        var result = new List<RawLoginEventInput>();
        foreach (var source in Sources)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var required = source == WindowsEventLogParser.SecuritySource;
            var health = required ? securityHealth : sshHealth;
            try
            {
                ReadSource(source, sinceUtc, result, cancellationToken);
                health.Recovered();
            }
            catch (EventLogNotFoundException)
            {
                // 未安装 OpenSSH/RDP/WinRM 日志通道时跳过该通道。
                if (required) health.Failed(permanent: true);
            }
            catch (EventLogException)
            {
                // 事件日志权限或通道异常只影响本轮采集，不能阻断 Agent。
                health.Failed(permanent: required);
            }
            catch (UnauthorizedAccessException)
            {
                // Agent 不是管理员时保留其他通道的采集结果。
                health.Failed(permanent: required);
            }
        }

        return Task.FromResult<IReadOnlyList<RawLoginEventInput>>(result);
    }

    private static void ReadSource(
        string source,
        DateTimeOffset sinceUtc,
        List<RawLoginEventInput> destination,
        CancellationToken cancellationToken)
    {
        var since = sinceUtc.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
        var timeFilter = $"TimeCreated[@SystemTime >= '{since}']";
        var filter = source == WindowsEventLogParser.SecuritySource
            ? $"*[System[(EventID=4624 or EventID=4625) and {timeFilter}]]"
            : $"*[System[{timeFilter}]]";
        var query = new EventLogQuery(source, PathType.LogName, filter)
        {
            ReverseDirection = false,
            TolerateQueryErrors = true
        };
        using var reader = new EventLogReader(query);
        EventRecord? record;
        while ((record = reader.ReadEvent()) is not null)
        {
            using (record)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (WindowsEventLogParser.TryParse(
                    source,
                    record.Id,
                    record.RecordId,
                    record.TimeCreated?.ToUniversalTime() ?? DateTimeOffset.UtcNow,
                    record.ToXml(),
                    source == WindowsEventLogParser.OpenSshSource ? ReadMessage(record) : null,
                    out var parsed))
                {
                    destination.Add(parsed);
                }
            }
        }
    }

    private static string? ReadMessage(EventRecord record)
    {
        try
        {
            return record.FormatDescription();
        }
        catch (EventLogException)
        {
            return null;
        }
    }
}

internal static partial class WindowsEventLogParser
{
    internal const string SecuritySource = "Security";
    internal const string OpenSshSource = "OpenSSH/Operational";

    public static bool TryParse(
        string source,
        int id,
        long? recordId,
        DateTimeOffset occurred,
        string? xml,
        string? formattedMessage,
        out RawLoginEventInput input)
    {
        input = default!;
        var values = ReadData(xml);
        var processName = First(values, "ProcessName", "ApplicationName", "ClientProcessName", "process");
        var processId = ParseInt(First(values, "ProcessId", "ClientProcessId"));
        ProtocolKind protocol;
        bool success;
        string? username;
        string? remoteIp;
        int? remotePort;
        var ambiguousEndpoint = false;
        if (source.Equals(OpenSshSource, StringComparison.OrdinalIgnoreCase))
        {
            var message = First(values, "payload") ?? formattedMessage ?? string.Empty;
            var match = OpenSshAuthentication().Match(message);
            if (!match.Success)
            {
                return false;
            }

            protocol = ProtocolKind.OpenSsh;
            success = match.Groups["result"].Value.Equals("Accepted", StringComparison.OrdinalIgnoreCase);
            // Failed none 是握手探测，Accepted none 则表示服务端实际接受了本次认证。
            if (!success && match.Groups["method"].Value.Equals("none", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            // 无效用户名及密钥描述可包含类似端点的文本。出现歧义时保留结果，禁止把猜测地址用于封禁。
            ambiguousEndpoint = OpenSshEndpointMarker().IsMatch(message.AsSpan(match.Index + match.Length));
            username = ambiguousEndpoint ? null : Clean(match.Groups["username"].Value);
            remoteIp = ambiguousEndpoint ? null : CleanIp(match.Groups["address"].Value);
            remotePort = ambiguousEndpoint ? null : ParsePort(match.Groups["port"].Value);
        }
        else if (source.Equals(SecuritySource, StringComparison.OrdinalIgnoreCase)
            && (id is 4624 or 4625) && values.Count > 0 && !LoginEventProtocol.IsOpenSshProcess(processName))
        {
            // 明确由 sshd 发起的系统认证属于 OpenSSH 的配套事件，避免与其认证结果重复计数。
            protocol = ResolveSecurityProtocol(values, processName);
            success = id == 4624;
            username = First(values, "TargetUserName", "User", "UserName", "AccountName");
            remoteIp = CleanIp(First(values, "IpAddress", "SourceNetworkAddress", "ClientIP", "ClientAddress", "RemoteAddress", "Address"));
            remotePort = ParsePort(First(values, "IpPort", "SourcePort", "ClientPort", "RemotePort"));
        }
        else
        {
            return false;
        }

        // 原生记录号只在单个通道内递增，同一连接中的独立认证结果各有自己的记录号。
        var rawId = recordId is { } number
            ? $"{source}:{number.ToString(CultureInfo.InvariantCulture)}"
            : $"{source}:{id}:{occurred:O}";
        var missingEndpoint = ambiguousEndpoint ? FieldAvailability.CorrelationFailed : FieldAvailability.NotProvided;

        input = new RawLoginEventInput(
            OccurredAtUtc: occurred,
            Protocol: protocol,
            Success: success,
            Username: Clean(username),
            RemoteIp: remoteIp,
            RemotePort: remotePort,
            LocalIp: null,
            LocalPort: null,
            LocalProcessId: processId,
            LocalProcessName: Clean(processName),
            OriginProcessId: null,
            OriginProcessName: null,
            Collector: $"windows-eventlog:{source}",
            RawEventId: rawId,
            EvidenceSource: $"eventlog:{source}:{id}",
            RemoteIpAvailability: remoteIp is null ? missingEndpoint : FieldAvailability.Available,
            RemotePortAvailability: remotePort is null ? missingEndpoint : FieldAvailability.Available,
            LocalEndpointAvailability: FieldAvailability.NotCollected,
            UsernameAvailability: string.IsNullOrWhiteSpace(Clean(username)) ? FieldAvailability.NotProvided : FieldAvailability.Available,
            ProcessAvailability: string.IsNullOrWhiteSpace(Clean(processName)) ? FieldAvailability.NotCollected : FieldAvailability.Available);
        return true;
    }

    private static ProtocolKind ResolveSecurityProtocol(IReadOnlyDictionary<string, string> values, string? processName)
    {
        if (First(values, "LogonType") == "10")
        {
            return ProtocolKind.Rdp;
        }

        if ((processName ?? First(values, "LogonProcessName")) is { } securityProcess
            && (securityProcess.Contains("wsmprovhost", StringComparison.OrdinalIgnoreCase)
                || securityProcess.Contains("winrshost", StringComparison.OrdinalIgnoreCase)
                || securityProcess.Contains("winrm", StringComparison.OrdinalIgnoreCase)))
        {
            return ProtocolKind.WinRm;
        }

        // 保留既有回环 WinRM 识别行为，远程 LogonType=3 不仅限 WinRM。
        if (First(values, "LogonType") == "3"
            && First(values, "IpAddress") is { } securityAddress
            && (securityAddress.Equals("::1", StringComparison.OrdinalIgnoreCase)
                || securityAddress.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase)))
        {
            return ProtocolKind.WinRm;
        }

        // 通用 Windows 安全事件缺少明确协议证据时，只保留可确认的认证结果和地址。
        return ProtocolKind.Unidentified;
    }

    private static Dictionary<string, string> ReadData(string? xml)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(xml))
        {
            return result;
        }

        try
        {
            var document = XDocument.Parse(xml, LoadOptions.None);
            foreach (var item in document.Descendants().Where(element => element.Name.LocalName.Equals("Data", StringComparison.OrdinalIgnoreCase)))
            {
                var name = item.Attribute("Name")?.Value;
                if (!string.IsNullOrWhiteSpace(name))
                {
                    result[name] = item.Value.Trim();
                }
            }

            // OpenSSH/Operational 通常只在 System/Execution 属性提供服务进程 PID。
            // Security 4624/4625 自带 EventData.ProcessId，优先保留更精确的字段。
            var execution = document.Descendants().FirstOrDefault(element =>
                element.Name.LocalName.Equals("Execution", StringComparison.OrdinalIgnoreCase));
            var executionProcessId = execution?.Attribute("ProcessID")?.Value;
            if (!string.IsNullOrWhiteSpace(executionProcessId) && !result.ContainsKey("ProcessId"))
            {
                result["ProcessId"] = executionProcessId;
            }
        }
        catch (System.Xml.XmlException)
        {
            // 事件 XML 损坏时回退到 FormatDescription 文本解析。
        }

        return result;
    }

    private static string? First(IReadOnlyDictionary<string, string> values, params string[] keys) =>
        keys.Select(key => values.TryGetValue(key, out var value) ? value : null)
            .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value) && value != "-");

    // 用户名可能含空格，匹配其后的结构化源地址和端口，而非按单个词截取用户名。
    [GeneratedRegex(@"^\s*(?:sshd(?:-session|-auth)?:\s*)?(?<result>Accepted|Failed)\s+(?<method>\S+)\s+for\s+(?:invalid\s+user\s+)?(?<username>[^\r\n]+?)\s+from\s+(?<address>\S+)\s+port\s+(?<port>[0-9]{1,5})\s+ssh2(?=[:\s]|$)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex OpenSshAuthentication();

    [GeneratedRegex(@"\s+from\s+\S+\s+port\s+[0-9]{1,5}\s+ssh2(?=[:\s]|$)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex OpenSshEndpointMarker();

    private static string? Clean(string? value) =>
        string.IsNullOrWhiteSpace(value) || value is "-" or "N/A" ? null : value.Trim();

    private static string? CleanIp(string? value) =>
        IPAddress.TryParse(Clean(value), out var address) ? address.ToString() : null;

    private static int? ParsePort(string? value) =>
        int.TryParse(Clean(value), NumberStyles.Integer, CultureInfo.InvariantCulture, out var port) && port is >= 1 and <= 65535 ? port : null;

    private static int? ParseInt(string? value) =>
        TryParseInt(Clean(value));

    private static int? TryParseInt(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            && int.TryParse(value.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hexResult))
        {
            return hexResult;
        }

        return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var decimalResult)
            ? decimalResult
            : null;
    }
}
