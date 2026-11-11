using System.Globalization;
using System.Net;
using System.Text;
using Microsoft.Extensions.Logging;

namespace IpBan.Shared.Logging.Syslog;

/// <summary>统一模块和严重级别。转发时不渲染任意结构化参数或异常正文。</summary>
internal static class SyslogEventCatalog
{
    public static SyslogSeverity Severity(LogLevel level) => level switch
    {
        LogLevel.Critical => SyslogSeverity.Critical,
        LogLevel.Error => SyslogSeverity.Error,
        LogLevel.Warning => SyslogSeverity.Warning,
        LogLevel.Information => SyslogSeverity.Informational,
        _ => SyslogSeverity.Debug
    };

    public static string Module(string category)
    {
        if (category.Contains("Syslog", StringComparison.Ordinal)) return "ipban-syslog";
        if (category.Contains("Notification", StringComparison.Ordinal)) return "ipban-mail";
        if (category.Contains("IpLocation", StringComparison.Ordinal) || category.Contains("GeoIp", StringComparison.OrdinalIgnoreCase)) return "ipban-geoip";
        if (category.Contains("Mcp", StringComparison.Ordinal)) return "ipban-mcp";
        if (category.Contains("Certificate", StringComparison.Ordinal)) return "ipban-cert";
        if (category.Contains("Backup", StringComparison.Ordinal)) return "ipban-backup";
        if (category.Contains("Audit", StringComparison.Ordinal)) return "ipban-audit";
        if (category.Contains("Ipc", StringComparison.Ordinal)) return "ipban-ipc";
        if (category.Contains("LoginCollector", StringComparison.Ordinal) || category.Contains("LoginEventCollection", StringComparison.Ordinal)) return "ipban-collector";
        if (category.Contains("Firewall", StringComparison.Ordinal)) return "ipban-firewall";
        if (category.Contains("AutomaticBan", StringComparison.Ordinal) || category.Contains("Policy", StringComparison.Ordinal)) return "ipban-policy";
        if (category.Contains("Session", StringComparison.Ordinal) || category.Contains("Connection", StringComparison.Ordinal)) return "ipban-session";
        if (category.Contains("FileLog", StringComparison.Ordinal)) return "ipban-logging";
        if (category.Contains("Sqlite", StringComparison.Ordinal) || category.Contains("Database", StringComparison.Ordinal)) return "ipban-storage";
        if (category.StartsWith("Microsoft.AspNetCore", StringComparison.Ordinal) || category.Contains("Realtime", StringComparison.Ordinal) ||
            category.Contains("Hub", StringComparison.Ordinal)) return "ipban-http";
        if (category.Contains("Settings", StringComparison.Ordinal) || category.Contains("Admin", StringComparison.Ordinal)) return "ipban-admin";
        return "ipban-runtime";
    }

    public static string RuntimeMessage<TState>(string category, LogLevel level, TState state, Exception? error)
    {
        var fallback = level switch
        {
            LogLevel.Critical => "运行组件发生严重故障。",
            LogLevel.Error => "运行组件执行失败。",
            LogLevel.Warning => "运行组件出现异常或降级。",
            LogLevel.Information => "运行组件报告状态。",
            _ => "运行组件报告诊断信息。"
        };
        var message = fallback;
        if (category.StartsWith("IpBan.", StringComparison.Ordinal) &&
            state is IReadOnlyList<KeyValuePair<string, object?>> fields)
        {
            var template = fields.FirstOrDefault(x => x.Key == "{OriginalFormat}").Value as string;
            if (template is not null && template.Any(c => c is >= '\u4e00' and <= '\u9fff'))
            {
                // 只转发项目预定义中文模板；任意字符串、对象和异常正文都可能带凭据。
                var output = new StringBuilder();
                for (var i = 0; i < template.Length && output.Length < 1024; i++)
                {
                    var close = template[i] == '{' ? template.IndexOf('}', i + 1) : -1;
                    if (close < 0)
                    {
                        output.Append(template[i]);
                        continue;
                    }
                    var key = template[(i + 1)..close].Split(',', ':')[0];
                    var value = fields.FirstOrDefault(x => x.Key == key).Value;
                    output.Append(value is int or long or double or bool or Enum
                        ? Convert.ToString(value, CultureInfo.InvariantCulture)
                        : RenderSafeField(key, value));
                    i = close;
                }
                message = output.ToString();
            }
        }
        return Clean(error is null ? message : $"{message} 异常类型：{error.GetType().Name}。", 1024)!;
    }

    private static string RenderSafeField(string key, object? value)
    {
        if (key is "SourceIp" or "SourceAddress" && value is string source)
        {
            if (IPAddress.TryParse(source, out var ip)) return ip.ToString();
            if (IPNetwork.TryParse(source, out var network)) return network.ToString();
        }
        if (key.Equals("time", StringComparison.OrdinalIgnoreCase) && value is DateTimeOffset time)
            return time.ToString("O", CultureInfo.InvariantCulture);
        if (key.Equals("provider", StringComparison.OrdinalIgnoreCase) && value is
            "firewalld" or "ufw" or "nftables" or "iptables" or "windows-defender-firewall-wfp")
            return (string)value;
        return "[已省略]";
    }

    public static string? Clean(string? value, int limit)
    {
        if (string.IsNullOrEmpty(value)) return value;
        var length = Math.Min(value.Length, limit);
        if (length < value.Length && char.IsHighSurrogate(value[length - 1])) length--;
        var output = new StringBuilder(length);
        foreach (var ch in value.AsSpan(0, length))
            output.Append(char.IsControl(ch) ? ' ' : ch);
        return output.ToString();
    }
}
