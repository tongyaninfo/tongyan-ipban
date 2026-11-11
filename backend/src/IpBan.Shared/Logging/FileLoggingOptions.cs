using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace IpBan.Shared.Logging;

/// <summary>
/// IPBan 结构化文件日志配置。普通日志允许尽力写入，可靠操作审计由独立存储负责。
/// </summary>
public sealed class FileLoggingOptions
{
    public const string SectionName = "Logging:File";

    public string Directory { get; set; } = "logs";

    public int RetentionDays { get; set; } = 365;

    public long MaxFileSizeBytes { get; set; } = 50 * 1024 * 1024;

    public bool CompressRotated { get; set; } = true;

    public LogLevel MinimumLevel { get; set; } = LogLevel.Information;

    public static FileLoggingOptions Load(IConfiguration configuration)
    {
        var section = configuration.GetSection(SectionName);
        var options = new FileLoggingOptions
        {
            Directory = section["Directory"] ?? "logs"
        };
        if (int.TryParse(section["RetentionDays"], out var retentionDays))
        {
            options.RetentionDays = retentionDays;
        }
        if (long.TryParse(section["MaxFileSizeBytes"], out var maxFileSizeBytes))
        {
            options.MaxFileSizeBytes = maxFileSizeBytes;
        }
        if (bool.TryParse(section["CompressRotated"], out var compressRotated))
        {
            options.CompressRotated = compressRotated;
        }
        if (Enum.TryParse<LogLevel>(section["MinimumLevel"], ignoreCase: true, out var minimumLevel))
        {
            options.MinimumLevel = minimumLevel;
        }

        return options;
    }
}

public sealed record FileLogEntry(
    DateTimeOffset TimestampUtc,
    string Level,
    string Category,
    int EventId,
    string Message,
    string? Exception,
    string? AppName = null,
    int? SyslogSeverity = null,
    string? EventType = null,
    string? Result = null,
    string? SourceId = null,
    string? RemoteIp = null,
    string? Actor = null);

public sealed record FileLogFileInfo(
    string Name,
    long SizeBytes,
    DateTimeOffset LastWriteTimeUtc,
    bool Compressed,
    bool CanDelete = false);

public enum FileLogDeleteStatus
{
    Deleted,
    InvalidName,
    Protected,
    NotFound,
    Unsafe,
    Busy
}
