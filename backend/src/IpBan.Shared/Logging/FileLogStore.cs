using System.IO.Compression;
using System.Text;
using System.Globalization;
using System.Text.Json;
using IpBan.Shared.Logging.Syslog;

namespace IpBan.Shared.Logging;

/// <summary>
/// 文件日志查询和导出服务。只读取 IPBan 自己的 NDJSON/压缩归档文件。
/// </summary>
public sealed class FileLogStore(FileLoggingOptions options, string contentRootPath, FileLoggerProvider? provider = null)
{
    private readonly string directory = FileLoggerProvider.ResolveDirectory(options.Directory, contentRootPath);
    private readonly object gate = provider?.SynchronizationGate ?? new object();

    public IReadOnlyList<FileLogFileInfo> ListFiles()
    {
        if (!Directory.Exists(directory))
        {
            return [];
        }

        var result = new List<FileLogFileInfo>();
        foreach (var path in Directory.EnumerateFiles(directory, "ipban-*.ndjson*"))
        {
            try
            {
                var file = new FileInfo(path);
                if (!IsManagedName(file.Name) || IsLinkedOrSpecial(file)) continue;
                result.Add(new FileLogFileInfo(file.Name, file.Length,
                    new DateTimeOffset(file.LastWriteTimeUtc, TimeSpan.Zero),
                    file.Name.EndsWith(".gz", StringComparison.Ordinal), CanDeleteCore(file.Name)));
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                // 另一进程可能正在轮转/删除，跳过已消失或不可读文件，避免整个列表失败。
            }
        }
        return result.OrderByDescending(file => file.LastWriteTimeUtc).ToArray();
    }

    public IReadOnlyList<string> ReadLines(string? fileName, string? keyword, int limit = 200,
        int? severity = null, string? appName = null)
    {
        var boundedLimit = Math.Clamp(limit, 1, 5000);
        var files = string.IsNullOrWhiteSpace(fileName)
            ? ListFiles().Select(info => info.Name)
            : [Path.GetFileName(fileName)];
        var result = new List<string>(boundedLimit);
        foreach (var name in files)
        {
            var path = Path.Combine(directory, name);
            if (!IsSafePath(path) || !File.Exists(path))
            {
                continue;
            }

            try
            {
                using var stream = OpenRead(name);
                using var reader = new StreamReader(stream, Encoding.UTF8);
                while (!reader.EndOfStream && result.Count < boundedLimit)
                {
                    var line = reader.ReadLine();
                    if (line is not null && (string.IsNullOrWhiteSpace(keyword)
                        || line.Contains(keyword, StringComparison.OrdinalIgnoreCase)) && MatchesSyslog(line, severity, appName))
                        result.Add(line);
                }
            }
            catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
            {
                // 存在检查之后仍可能发生并发删除；其余日志继续查询。
                continue;
            }

            if (result.Count >= boundedLimit)
            {
                break;
            }
        }

        return result;
    }

    private static bool MatchesSyslog(string line, int? severity, string? appName)
    {
        if (severity is null && string.IsNullOrEmpty(appName)) return true;
        try
        {
            using var document = JsonDocument.Parse(line);
            var entry = document.RootElement;
            if (entry.ValueKind != JsonValueKind.Object) return false;
            if (severity is { } expected)
            {
                // 旧归档只有 .NET 级别，显式 Syslog 级别优先。
                if (entry.TryGetProperty("syslogSeverity", out var value) && value.ValueKind == JsonValueKind.Number
                    && value.TryGetInt32(out var assigned))
                {
                    if (assigned != expected) return false;
                }
                else if (!entry.TryGetProperty("level", out var level) || level.ValueKind != JsonValueKind.String
                    || LegacySeverity(level.GetString()) != expected) return false;
            }
            return string.IsNullOrEmpty(appName) || (entry.TryGetProperty("appName", out var module)
                && module.ValueKind == JsonValueKind.String && module.ValueEquals(appName));
        }
        catch (JsonException) { return false; }
    }

    private static int LegacySeverity(string? value) => value switch
    {
        "Critical" => (int)SyslogSeverity.Critical,
        "Error" => (int)SyslogSeverity.Error,
        "Warning" => (int)SyslogSeverity.Warning,
        "Information" => (int)SyslogSeverity.Informational,
        "Trace" or "Debug" => (int)SyslogSeverity.Debug,
        _ => -1
    };

    public Stream OpenRead(string fileName)
    {
        var path = Path.Combine(directory, Path.GetFileName(fileName));
        if (!IsSafePath(path) || !File.Exists(path))
        {
            throw new FileNotFoundException("日志文件不存在。", fileName);
        }

        return path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)
            ? new GZipStream(OpenSharedRead(path), CompressionMode.Decompress)
            : OpenSharedRead(path);
    }

    /// <summary>只删除单个已轮转归档；检查与删除共用writer门闩，并取得跨进程归档/目标租约。</summary>
    public FileLogDeleteStatus DeleteFile(string fileName)
    {
        lock (gate)
        {
            if (ValidateArchiveName(fileName) is { } invalid) return invalid;
            try
            {
                if (!Directory.Exists(directory)) return FileLogDeleteStatus.NotFound;
                if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
                    return FileLogDeleteStatus.Unsafe;
                using var archiveLease = FileLoggerProvider.OpenArchiveLease(directory);
                if (InspectArchive(fileName) is { } rejected) return rejected;
                var path = Path.Combine(directory, fileName);
                using var targetLease = FileLoggerProvider.OpenDeletionLease(path);
                if (!targetLease.CanSeek || InspectArchive(fileName) is not null)
                    return FileLogDeleteStatus.Unsafe;
                File.Delete(path);
                return FileLogDeleteStatus.Deleted;
            }
            catch (FileNotFoundException) { return FileLogDeleteStatus.NotFound; }
            catch (DirectoryNotFoundException) { return FileLogDeleteStatus.NotFound; }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            { return FileLogDeleteStatus.Busy; }
        }
    }

    /// <summary>审计只接收受管文件名，不把提交的路径或任意内容写入可靠审计。</summary>
    public static string GetAuditTarget(string fileName) => IsManagedName(fileName) ? fileName : "invalid-log-file";

    private bool CanDeleteCore(string fileName)
    {
        if (ValidateArchiveName(fileName) is not null) return false;
        try
        {
            if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0 || InspectArchive(fileName) is not null)
                return false;
            // 列表只标注静态资格；真正删除时再取得排他租约，避免普通并发查询使按钮闪烁。
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException) { return false; }
    }

    private FileLogDeleteStatus? InspectArchive(string fileName)
    {
        var path = Path.Combine(directory, fileName);
        var attributes = File.GetAttributes(path);
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0)
            return FileLogDeleteStatus.Unsafe;
        var file = new FileInfo(path);
        // 保守保护空归档，避免打开零长度FIFO、套接字或设备；普通归档还必须支持seek。
        return IsLinkedOrSpecial(file) || file.Length <= 0 ? FileLogDeleteStatus.Unsafe : null;
    }

    private static bool IsLinkedOrSpecial(FileInfo file) =>
        (file.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0
        || file.LinkTarget is not null;

    private static bool IsManagedName(string name) => IsDailyName(name) || IsArchiveName(name);

    private static FileLogDeleteStatus? ValidateArchiveName(string name) =>
        IsDailyName(name) ? FileLogDeleteStatus.Protected
        : IsArchiveName(name) ? null : FileLogDeleteStatus.InvalidName;

    private static bool IsDailyName(string name) => name.Length == 21
        && name.StartsWith("ipban-", StringComparison.Ordinal)
        && name.EndsWith(".ndjson", StringComparison.Ordinal)
        && DateOnly.TryParseExact(name.AsSpan(6, 8), "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out _);

    private static bool IsArchiveName(string name)
    {
        var raw = name.EndsWith(".gz", StringComparison.Ordinal) ? name[..^3] : name;
        return raw.Length == 31 && raw[21] == '.' && IsDailyName(raw[..21])
            && TimeOnly.TryParseExact(raw.AsSpan(22, 9), "HHmmssfff", CultureInfo.InvariantCulture, DateTimeStyles.None, out _);
    }

    private static FileStream OpenSharedRead(string path) =>
        new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

    private bool IsSafePath(string path) =>
        Path.GetFullPath(path).StartsWith(Path.GetFullPath(directory) + Path.DirectorySeparatorChar, StringComparison.Ordinal);
}
