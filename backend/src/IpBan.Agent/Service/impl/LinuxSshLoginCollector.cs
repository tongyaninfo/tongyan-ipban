using System.Globalization;
using System.Text.Json;
using IpBan.Agent.Options;
using IpBan.Shared.Logging.Syslog;
using IpBan.Shared.Models;
using Microsoft.Extensions.Options;

namespace IpBan.Agent.Service.impl;

/// <summary>
/// 通过 journalctl 读取 sshd 结构化日志。命令使用 ArgumentList，禁止 shell 拼接。
/// </summary>
public sealed class LinuxSshLoginCollector(IOptions<LinuxSshCollectorOptions> options, SyslogRuntime? syslog = null) : ILoginEventCollector
{
    private readonly CollectorLogHealth health = new(syslog, "SSH");
    public string Name => "linux-sshd-journald";

    public ProtocolKind Protocol => ProtocolKind.Ssh;

    public async Task<IReadOnlyList<RawLoginEventInput>> CollectAsync(
        DateTimeOffset sinceUtc,
        CancellationToken cancellationToken = default)
    {
        var collectorOptions = options.Value;
        if (!OperatingSystem.IsLinux() || !collectorOptions.Enabled)
        {
            return Array.Empty<RawLoginEventInput>();
        }

        var startInfo = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "journalctl",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            // 错误流不参与事件解析，保持关闭以避免 journalctl 异常输出导致管道阻塞。
            RedirectStandardError = false,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add($"--unit={collectorOptions.Unit}");
        startInfo.ArgumentList.Add("--since");
        startInfo.ArgumentList.Add(sinceUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        startInfo.ArgumentList.Add("--no-pager");
        startInfo.ArgumentList.Add("--output=json");
        startInfo.ArgumentList.Add($"--lines={collectorOptions.MaxLines}");

        using var process = new System.Diagnostics.Process { StartInfo = startInfo };
        try
        {
            if (!process.Start())
            {
                health.Failed();
                return Array.Empty<RawLoginEventInput>();
            }

            var output = await process.StandardOutput.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            if (process.ExitCode != 0)
            {
                health.Failed();
                return Array.Empty<RawLoginEventInput>();
            }

            health.Recovered();
            return ParseJournalOutput(output);
        }
        catch (FileNotFoundException)
        {
            health.Failed();
            return Array.Empty<RawLoginEventInput>();
        }
        catch (UnauthorizedAccessException)
        {
            health.Failed(permanent: true);
            return Array.Empty<RawLoginEventInput>();
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // journalctl 不存在或无法启动只影响采集，明确记录源故障。
            health.Failed();
            return Array.Empty<RawLoginEventInput>();
        }
    }

    internal static IReadOnlyList<RawLoginEventInput> ParseJournalOutput(string output)
    {
        var events = new List<RawLoginEventInput>();
        using var reader = new StringReader(output);
        while (reader.ReadLine() is { } line)
        {
            if (TryParseJournalLine(line, out var loginEvent))
            {
                events.Add(loginEvent);
            }
        }

        return events;
    }

    private static bool TryParseJournalLine(string line, out RawLoginEventInput loginEvent)
    {
        loginEvent = default!;
        try
        {
            using var document = JsonDocument.Parse(line);
            var root = document.RootElement;
            if (!root.TryGetProperty("MESSAGE", out var messageProperty)
                || messageProperty.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            var timestamp = ReadTimestamp(root);
            var rawEventId = ReadString(root, "__CURSOR");
            var processId = ReadInt32(root, "_PID");
            return LinuxSshLoginParser.TryParse(
                messageProperty.GetString() ?? string.Empty,
                timestamp,
                rawEventId,
                processId,
                out loginEvent);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static DateTimeOffset ReadTimestamp(JsonElement root)
    {
        var value = ReadString(root, "__REALTIME_TIMESTAMP");
        return long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var microseconds)
            ? DateTimeOffset.UnixEpoch.AddTicks(microseconds * 10).ToUniversalTime()
            : DateTimeOffset.UtcNow;
    }

    private static string? ReadString(JsonElement root, string propertyName)
    {
        if (!root.TryGetProperty(propertyName, out var property))
        {
            return null;
        }

        return property.ValueKind switch
        {
            JsonValueKind.String => property.GetString(),
            // journalctl 通常把字段输出为字符串；兼容结构化回放中使用数字的情况。
            JsonValueKind.Number => property.ToString(),
            _ => null
        };
    }

    private static int? ReadInt32(JsonElement root, string propertyName)
    {
        var value = ReadString(root, propertyName);
        return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var result)
            ? result
            : null;
    }
}
