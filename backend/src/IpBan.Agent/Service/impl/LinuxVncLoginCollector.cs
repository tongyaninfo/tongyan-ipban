using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using IpBan.Agent.Options;
using IpBan.Shared.Models;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;

namespace IpBan.Agent.Service.impl;

/// <summary>
/// 读取 TigerVNC journal 或文件。最近结果可重放，交由持久化层确认幂等写入。
/// </summary>
public sealed partial class LinuxVncLoginCollector(IOptions<LinuxVncCollectorOptions> options,
    ILogger<LinuxVncLoginCollector> logger) : ILoginEventCollector
{
    private static readonly string[] RootHome = ["/root"];
    private readonly Dictionary<string, TigerVncLoginParser> journalParsers = new(StringComparer.Ordinal);
    private readonly HashSet<string> journalRecords = new(StringComparer.Ordinal);
    private readonly Dictionary<string, FileTail> files = new(StringComparer.Ordinal);
    private readonly Dictionary<string, RawLoginEventInput> recentEvents = new(StringComparer.Ordinal);

    public string Name => "linux-tigervnc";
    public ProtocolKind Protocol => ProtocolKind.Vnc;

    public async Task<IReadOnlyList<RawLoginEventInput>> CollectAsync(DateTimeOffset sinceUtc, CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsLinux() || !options.Value.Enabled)
        {
            return [];
        }
        return await ReadAsync(sinceUtc, cancellationToken).ConfigureAwait(false);
    }

    internal async Task<IReadOnlyList<RawLoginEventInput>> ReadAsync(DateTimeOffset sinceUtc, CancellationToken cancellationToken = default)
    {
        var config = options.Value;
        var earliest = sinceUtc.AddSeconds(-config.LookbackSeconds);
        if (config.Source.Equals("Files", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var path in ResolveLogFiles(config.LogFiles))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!files.TryGetValue(path, out var tail))
                {
                    tail = new FileTail();
                    files.Add(path, tail);
                }
                try
                {
                    foreach (var item in await tail.ReadAsync(path, config.MaxFileBytesPerPoll, cancellationToken).ConfigureAwait(false))
                    {
                        Remember(item);
                    }
                }
                catch (FileNotFoundException)
                {
                    // 日志在枚举后轮转时留待下轮重新发现。
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    LogSourceReadFailed(exception, path);
                }
            }
        }
        else
        {
            ParseJournalOutput(await ReadJournalAsync(earliest, config, cancellationToken).ConfigureAwait(false));
        }

        foreach (var key in recentEvents.Where(pair => pair.Value.OccurredAtUtc < earliest).Select(pair => pair.Key).ToArray())
        {
            recentEvents.Remove(key);
        }
        return recentEvents.Values.OrderBy(item => item.OccurredAtUtc).ToArray();
    }

    internal IReadOnlyList<RawLoginEventInput> ParseJournalOutput(string output)
    {
        var results = new List<RawLoginEventInput>();
        using var reader = new StringReader(output);
        while (reader.ReadLine() is { } line)
        {
            try
            {
                using var document = JsonDocument.Parse(line);
                var root = document.RootElement;
                var message = ReadString(root, "MESSAGE");
                var cursor = ReadString(root, "__CURSOR");
                if (message is null || cursor is null || !journalRecords.Add(cursor))
                {
                    continue;
                }
                var process = ReadString(root, "_COMM");
                var source = string.Join(':', ReadString(root, "_BOOT_ID"), ReadString(root, "_SYSTEMD_UNIT"),
                    ReadString(root, "_PID"), ReadString(root, "SYSLOG_IDENTIFIER"));
                if (!journalParsers.TryGetValue(source, out var parser))
                {
                    parser = new TigerVncLoginParser();
                    journalParsers.Add(source, parser);
                }
                var timestamp = long.TryParse(ReadString(root, "__REALTIME_TIMESTAMP"), CultureInfo.InvariantCulture, out var microseconds)
                    ? DateTimeOffset.UnixEpoch.AddTicks(microseconds * 10) : (DateTimeOffset?)null;
                // 转发日志的 systemd-cat PID 不属于 Xvnc，留给连接快照关联。
                var processId = process is "Xvnc" or "Xtigervnc"
                    && int.TryParse(ReadString(root, "_PID"), CultureInfo.InvariantCulture, out var parsedPid) ? parsedPid : (int?)null;
                var item = parser.Parse(message, "journal:tigervnc", $"vnc-journal:{cursor}", timestamp, processId, process);
                if (item is not null)
                {
                    Remember(item);
                    results.Add(item);
                }
            }
            catch (JsonException)
            {
                // 一条损坏的 journal 记录不影响其他认证证据。
            }
            catch (ArgumentOutOfRangeException)
            {
                // 超出日期范围的 journal 元数据只丢弃当前条目。
            }
        }
        if (journalRecords.Count > 50000)
        {
            // 重新建立上下文时与事件 ID 一起回放，由事件缓存及数据库去重。
            journalRecords.Clear();
            journalParsers.Clear();
        }
        return results;
    }

    private void Remember(RawLoginEventInput item)
    {
        recentEvents.TryAdd(item.RawEventId!, item);
    }

    private static async Task<string> ReadJournalAsync(DateTimeOffset sinceUtc, LinuxVncCollectorOptions config, CancellationToken token)
    {
        var start = new ProcessStartInfo("journalctl")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var argument in new[] { "--no-pager", "--output=json", "--since", sinceUtc.ToString("O", CultureInfo.InvariantCulture),
                     $"--lines={config.MaxLines.ToString(CultureInfo.InvariantCulture)}", "_COMM=Xvnc", "+", "_COMM=Xtigervnc" })
        {
            start.ArgumentList.Add(argument);
        }
        foreach (var identifier in config.JournalIdentifiers)
        {
            start.ArgumentList.Add("+");
            start.ArgumentList.Add($"SYSLOG_IDENTIFIER={identifier}");
        }
        using var process = new Process { StartInfo = start };
        try
        {
            process.Start();
        }
        catch (System.ComponentModel.Win32Exception exception)
        {
            throw new IOException("TigerVNC journal 读取程序无法启动。", exception);
        }
        var output = process.StandardOutput.ReadToEndAsync(token);
        var error = process.StandardError.ReadToEndAsync(token);
        await process.WaitForExitAsync(token).ConfigureAwait(false);
        await error.ConfigureAwait(false);
        if (process.ExitCode != 0)
        {
            throw new IOException("TigerVNC journal 查询失败。");
        }
        return await output.ConfigureAwait(false);
    }

    private static string? ReadString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind is JsonValueKind.String or JsonValueKind.Number
            ? value.ToString() : null;

    private HashSet<string> ResolveLogFiles(string[] paths)
    {
        IEnumerable<string> patterns = paths.Length > 0 ? paths : DefaultLogPatterns();
        var resolved = new HashSet<string>(StringComparer.Ordinal);
        foreach (var pattern in patterns)
        {
            try
            {
                resolved.UnionWith(ExpandPattern(pattern).Take(64 - resolved.Count));
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                LogSourceReadFailed(exception, pattern);
            }
            if (resolved.Count >= 64)
            {
                break;
            }
        }
        return resolved;
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "TigerVNC 日志源 {Source} 本轮读取失败，其余日志源继续采集")]
    private partial void LogSourceReadFailed(Exception exception, string source);

    private static IEnumerable<string> DefaultLogPatterns()
    {
        var homes = RootHome.Concat(Directory.Exists("/home") ? Directory.EnumerateDirectories("/home").Take(128) : []);
        foreach (var home in homes)
        {
            yield return Path.Combine(home, ".vnc", "*.log");
            yield return Path.Combine(home, ".local", "state", "tigervnc", "*.log");
        }
        yield return "/var/log/tigervnc/*.log";
    }

    private static IEnumerable<string> ExpandPattern(string pattern)
    {
        var directory = Path.GetDirectoryName(pattern);
        return directory is not null && Directory.Exists(directory)
            ? Directory.EnumerateFiles(directory, Path.GetFileName(pattern), SearchOption.TopDirectoryOnly)
            : [];
    }

    /// <summary>
    /// 只提交完整行。前缀和游标前锚点检测替换，长度缩短检测 copytruncate。
    /// </summary>
    private sealed class FileTail
    {
        private long position;
        private byte[] prefix = [];
        private byte[] anchor = [];
        private TigerVncLoginParser parser = new();
        private bool initialized;

        public async Task<IReadOnlyList<RawLoginEventInput>> ReadAsync(string path, int limit, CancellationToken token)
        {
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.Asynchronous);
            if (stream.Length < position || !await MatchesAsync(stream, 0, prefix, token).ConfigureAwait(false)
                || !await MatchesAsync(stream, position - anchor.Length, anchor, token).ConfigureAwait(false))
            {
                position = 0;
                prefix = [];
                anchor = [];
                parser = new TigerVncLoginParser();
                initialized = false;
            }
            // 首次打开大日志只重建有界尾部，历史文件不能堵塞当前认证的采集。
            var skipFirstLine = !initialized && stream.Length > limit;
            if (!initialized)
            {
                position = Math.Max(0, stream.Length - limit);
                initialized = true;
            }
            if (prefix.Length == 0 && stream.Length > 0)
            {
                prefix = new byte[(int)Math.Min(256, stream.Length)];
                stream.Position = 0;
                await stream.ReadExactlyAsync(prefix, token).ConfigureAwait(false);
            }
            stream.Position = position;
            var bytes = new byte[(int)Math.Min(limit, Math.Max(0, stream.Length - position))];
            var read = await stream.ReadAsync(bytes, token).ConfigureAwait(false);
            var results = new List<RawLoginEventInput>();
            var beginning = 0;
            for (var index = 0; index < read; index++)
            {
                if (bytes[index] != (byte)'\n')
                {
                    continue;
                }
                if (skipFirstLine)
                {
                    beginning = index + 1;
                    skipFirstLine = false;
                    continue;
                }
                var line = Encoding.UTF8.GetString(bytes, beginning, index - beginning).TrimEnd('\r');
                var offset = position + beginning;
                var id = $"vnc-file:{TigerVncLoginParser.StableId($"{path}|{offset}|{line}")}";
                var item = parser.Parse(line, $"file:{path}", id);
                if (item is not null)
                {
                    results.Add(item);
                }
                beginning = index + 1;
            }
            // 超长单行不能让采集永远卡住；丢弃该残段并重建上下文，等待下个有效日期块。
            if (beginning == 0 && read == limit)
            {
                beginning = read;
                parser = new TigerVncLoginParser();
            }
            position += beginning;
            anchor = new byte[(int)Math.Min(128, position)];
            stream.Position = position - anchor.Length;
            await stream.ReadExactlyAsync(anchor, token).ConfigureAwait(false);
            return results;
        }

        private static async Task<bool> MatchesAsync(FileStream stream, long start, byte[] expected, CancellationToken token)
        {
            if (expected.Length == 0)
            {
                return true;
            }
            if (start < 0 || stream.Length < start + expected.Length)
            {
                return false;
            }
            var actual = new byte[expected.Length];
            stream.Position = start;
            await stream.ReadExactlyAsync(actual, token).ConfigureAwait(false);
            return actual.AsSpan().SequenceEqual(expected);
        }
    }
}
