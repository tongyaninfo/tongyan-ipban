using System.IO.Compression;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using IpBan.Shared.Logging.Syslog;

namespace IpBan.Shared.Logging;

/// <summary>
/// 轻量级 NDJSON 文件日志 Provider，支持按日期/大小轮转和 gzip 压缩。
/// 写文件失败只影响普通日志，不阻断 Agent/API 主流程。
/// </summary>
public sealed class FileLoggerProvider : ILoggerProvider, ISupportExternalScope
{
    private readonly object gate = new();
    internal object SynchronizationGate => gate;
    private readonly FileLoggingOptions options;
    private readonly string directory;
    private StreamWriter? writer;
    private string? activePath;
    private DateOnly activeDay;
    private long writeFailures;
    private long archiveFailures;
    private long lastWriteUtcTicks;
    private IExternalScopeProvider scopeProvider = new LoggerExternalScopeProvider();

    public FileLoggerProvider(FileLoggingOptions options, string contentRootPath)
    {
        this.options = Normalize(options);
        directory = ResolveDirectory(this.options.Directory, contentRootPath);
        Directory.CreateDirectory(directory);
        PruneExpiredFiles();
    }

    public ILogger CreateLogger(string categoryName) =>
        new FileLogger(this, categoryName, () => scopeProvider);

    public void SetScopeProvider(IExternalScopeProvider scopeProvider) =>
        this.scopeProvider = scopeProvider ?? new LoggerExternalScopeProvider();

    public void Dispose()
    {
        lock (gate)
        {
            writer?.Dispose();
            writer = null;
            activePath = null;
        }
    }

    internal bool IsEnabled(LogLevel level) => level >= options.MinimumLevel && level != LogLevel.None;

    internal SyslogLocalLogStatus GetStatus()
    {
        var ticks = Interlocked.Read(ref lastWriteUtcTicks);
        return new(Interlocked.Read(ref writeFailures), Interlocked.Read(ref archiveFailures),
            ticks == 0 ? null : new DateTimeOffset(ticks, TimeSpan.Zero));
    }

    internal void Write(
        string categoryName,
        LogLevel level,
        EventId eventId,
        string message,
        Exception? exception)
    {
        if (!IsEnabled(level))
        {
            return;
        }

        var entry = new FileLogEntry(
            DateTimeOffset.UtcNow,
            level.ToString(),
            categoryName,
            eventId.Id,
            message,
            exception?.GetType().Name,
            SyslogEventCatalog.Module(categoryName),
            (int)SyslogEventCatalog.Severity(level));
        WriteEntry(entry);
    }

    internal void WriteSyslogEvent(SyslogEvent entry)
    {
        var level = entry.Severity switch
        {
            SyslogSeverity.Emergency or SyslogSeverity.Alert or SyslogSeverity.Critical => LogLevel.Critical,
            SyslogSeverity.Error => LogLevel.Error,
            SyslogSeverity.Warning => LogLevel.Warning,
            SyslogSeverity.Debug => LogLevel.Debug,
            _ => LogLevel.Information
        };
        if (IsEnabled(level))
            WriteEntry(new FileLogEntry(entry.OccurredAtUtc, level.ToString(), entry.AppName, 0, entry.Message, null,
                entry.AppName, (int)entry.Severity, entry.EventType, entry.Result, entry.SourceId, entry.RemoteIp, entry.Actor));
    }

    private void WriteEntry(FileLogEntry entry)
    {
        var line = JsonSerializer.Serialize(entry, IpBanLogJsonContext.Default.FileLogEntry) + Environment.NewLine;

        try
        {
            lock (gate)
            {
                EnsureWriter(DateTimeOffset.UtcNow, Encoding.UTF8.GetByteCount(line));
                writer!.Write(line);
                writer.Flush();
                Interlocked.Exchange(ref lastWriteUtcTicks, DateTimeOffset.UtcNow.UtcTicks);
            }
        }
        catch
        {
            Interlocked.Increment(ref writeFailures);
            // 文件日志是尽力记录，不让磁盘权限/空间故障拖垮业务线程。
        }
    }

    private void EnsureWriter(DateTimeOffset timestampUtc, int incomingBytes)
    {
        var day = DateOnly.FromDateTime(timestampUtc.UtcDateTime);
        var expectedPath = Path.Combine(directory, $"ipban-{day:yyyyMMdd}.ndjson");
        var activeFile = writer is not null && activePath is not null ? new FileInfo(activePath) : null;
        // Agent 和 API 共享目录时，另一个进程可能已经将原路径移入归档。
        var needsDateRotation = activeFile?.Exists != true || !string.Equals(activePath, expectedPath, StringComparison.Ordinal);
        var needsSizeRotation = !needsDateRotation
            && options.MaxFileSizeBytes > 0
            && activeFile!.Length + incomingBytes > options.MaxFileSizeBytes;

        if (needsDateRotation || needsSizeRotation)
        {
            RotateActiveFile();
        }

        if (writer is null)
        {
            activeDay = day;
            activePath = expectedPath;
            writer = new StreamWriter(
                new FileStream(activePath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite),
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false))
            {
                AutoFlush = false
            };
        }
    }

    private void RotateActiveFile()
    {
        if (string.IsNullOrWhiteSpace(activePath) || !File.Exists(activePath))
        {
            writer?.Dispose();
            writer = null;
            activePath = null;
            return;
        }

        FileStream lease;
        try { lease = OpenArchiveLease(directory); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // 其他进程正在轮转/删除时保留现有writer，继续追加，下一次写入再尝试轮转。
            return;
        }
        using var archiveLease = lease;
        writer?.Dispose();
        writer = null;
        var suffix = DateTimeOffset.UtcNow.ToString("HHmmssfff", CultureInfo.InvariantCulture);
        var rotatedPath = $"{activePath}.{suffix}";
        try
        {
            File.Move(activePath, rotatedPath, overwrite: false);
            if (options.CompressRotated)
            {
                // 另一Agent/API仍持有已改名inode时不压缩、不删除；完整gzip才发布为可见归档。
                using var source = OpenDeletionLease(rotatedPath);
                var pendingPath = rotatedPath + ".gz.pending";
                using (var target = new FileStream(pendingPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (var gzip = new GZipStream(target, CompressionLevel.Fastest))
                    source.CopyTo(gzip);
                File.Move(pendingPath, rotatedPath + ".gz", overwrite: false);
                File.Delete(rotatedPath);
            }
        }
        catch
        {
            Interlocked.Increment(ref archiveFailures);
            // 下次写入仍会创建新的活动文件；轮转失败不阻断业务。
        }

        activePath = null;
    }

    private void PruneExpiredFiles()
    {
        try
        {
            using var archiveLease = OpenArchiveLease(directory);
            var cutoff = DateTimeOffset.UtcNow.AddDays(-options.RetentionDays);
            foreach (var path in Directory.EnumerateFiles(directory, "ipban-*.ndjson*"))
            {
                try
                {
                    var file = new FileInfo(path);
                    if (!file.Exists || file.LastWriteTimeUtc >= cutoff.UtcDateTime
                        || (file.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0
                        || file.Length == 0)
                        continue;

                    using var targetLease = OpenDeletionLease(path);
                    File.Delete(path);
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    // 单个文件仍被另一个进程占用时，继续清理其他归档。
                }
            }
        }
        catch
        {
            Interlocked.Increment(ref archiveFailures);
            // 启动清理失败由日志状态接口暴露，不阻止服务启动。
        }
    }

    // 两个宿主可共用日志目录；此租约覆盖轮转、压缩、清理及手动删除的跨进程窗口。
    internal static FileStream OpenArchiveLease(string directory)
    {
        var path = Path.Combine(directory, ".ipban-archive.lock");
        var file = new FileInfo(path);
        if (file.LinkTarget is not null || Directory.Exists(path)
            || file.Exists && (file.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new IOException("日志目录锁不可用。");
        return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    }

    internal static string ResolveDirectory(string configuredDirectory, string contentRootPath)
    {
        var value = string.IsNullOrWhiteSpace(configuredDirectory) ? "logs" : configuredDirectory;
        var path = Path.GetFullPath(Path.IsPathRooted(value) ? value : Path.Combine(contentRootPath, value));
        var directory = new DirectoryInfo(path);
        // 部署可能通过目录链接保留历史日志，固定配置指定的物理目录。
        return Path.TrimEndingDirectorySeparator(directory.Exists
            ? directory.ResolveLinkTarget(returnFinalTarget: true)?.FullName ?? path
            : path);
    }

    internal static FileStream OpenDeletionLease(string path) =>
        new(path, FileMode.Open, FileAccess.Read, OperatingSystem.IsWindows() ? FileShare.Delete : FileShare.None);

    private static FileLoggingOptions Normalize(FileLoggingOptions value) =>
        new()
        {
            Directory = string.IsNullOrWhiteSpace(value.Directory) ? "logs" : value.Directory,
            RetentionDays = Math.Clamp(value.RetentionDays, 1, 3650),
            MaxFileSizeBytes = Math.Clamp(value.MaxFileSizeBytes, 1024 * 1024, 1024L * 1024 * 1024),
            CompressRotated = value.CompressRotated,
            MinimumLevel = value.MinimumLevel
        };

    private sealed class FileLogger(
        FileLoggerProvider provider,
        string categoryName,
        Func<IExternalScopeProvider> getScopeProvider) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull =>
            getScopeProvider().Push(state);

        public bool IsEnabled(LogLevel logLevel) => provider.IsEnabled(logLevel);

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            provider.Write(categoryName, logLevel, eventId, SyslogEventCatalog.RuntimeMessage(categoryName, logLevel, state, exception), exception);
        }
    }
}

public static class FileLoggingExtensions
{
    public static ILoggingBuilder AddIpBanFileLogging(
        this ILoggingBuilder builder,
        IConfiguration configuration,
        string contentRootPath)
    {
        var options = FileLoggingOptions.Load(configuration);
        var provider = new FileLoggerProvider(options, contentRootPath);
        builder.Services.AddSingleton(provider);
        builder.AddProvider(provider);
        return builder;
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(FileLogEntry))]
internal sealed partial class IpBanLogJsonContext : JsonSerializerContext
{
}
