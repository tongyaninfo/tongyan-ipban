using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;

namespace IpBan.Shared.Logging.Syslog;

/// <summary>独立待发分段；分段完整写盘后发布，确认游标通过同目录改名保存。</summary>
internal sealed class SyslogDiskSpool : IDisposable
{
    private const long ProcessLimit = 384L * 1024 * 1024;
    private const long DestinationLimit = 128L * 1024 * 1024;
    private const int SegmentLimit = 8192;
    private const int SegmentBytes = 1024 * 1024;
    private readonly Lock gate = new();
    private readonly List<Segment> segments = [];
    private readonly string directory;
    private FileStream? lease;

    public SyslogDiskSpool(string directory) => this.directory = directory;
    public void Dispose() => Close();

    public readonly record struct Destination(string Id, string Version)
    {
        public static Destination From(SyslogTarget target) => new(target.Id, target.DeliveryTargetVersion);
    }

    public sealed record Segment(Destination Target, bool Priority, bool Diagnostic, DateTimeOffset Created, Guid Id, int Count, int Offset, long Bytes)
    {
        public string Name => FormattableString.Invariant(
            $"{Target.Id}.{Target.Version}.{(Priority ? 1 : Diagnostic ? 2 : 0)}.{Created.UtcTicks:D19}.{Id:N}.{Count}.{Offset}.sysq");
    }

    public static bool SafeKey(string? key) => key is { Length: > 0 and <= 64 } &&
        key.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    public void Open()
    {
        lock (gate)
        {
            Directory.CreateDirectory(directory);
            if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Syslog 缓冲目录不能为链接。");
            lease = new FileStream(Path.Combine(directory, ".lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            try
            {
                foreach (var path in Directory.EnumerateFiles(directory, "*.sysq"))
                {
                    var file = new FileInfo(path);
                    if ((file.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                    var p = file.Name.Split('.');
                    if (p.Length != 8 || !SafeKey(p[0]) || !SafeKey(p[1]) || p[2] is not ("0" or "1" or "2") ||
                        !long.TryParse(p[3], NumberStyles.None, CultureInfo.InvariantCulture, out var ticks) ||
                        ticks < 0 || ticks > DateTimeOffset.MaxValue.UtcTicks ||
                        !Guid.TryParseExact(p[4], "N", out var id) ||
                        !int.TryParse(p[5], NumberStyles.None, CultureInfo.InvariantCulture, out var count) ||
                        !int.TryParse(p[6], NumberStyles.None, CultureInfo.InvariantCulture, out var offset) ||
                        count is < 1 or > 64 || offset < 0 || offset >= count) continue;
                    var segment = new Segment(new(p[0], p[1]), p[2] == "1", p[2] == "2", new(ticks, TimeSpan.Zero), id, count, offset, file.Length);
                    if (segment.Name == file.Name) segments.Add(segment);
                }
                // 未完成发布的临时分段不可能已投递，启动后由缓冲生命周期回收。
                foreach (var path in Directory.EnumerateFiles(directory, "*.pending"))
                    if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0 && Guid.TryParseExact(Path.GetFileNameWithoutExtension(path), "N", out _))
                        File.Delete(path);
            }
            catch
            {
                Close();
                throw;
            }
        }
    }

    public void Close()
    {
        lock (gate)
        {
            lease?.Dispose();
            lease = null;
            segments.Clear();
        }
    }

    public bool Append(Destination target, bool priority, bool diagnostic, SyslogEvent[] events, DateTimeOffset now)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(events, SyslogJsonContext.Default.SyslogEventArray);
        var size = bytes.LongLength + 32;
        lock (gate)
        {
            var total = segments.Sum(x => x.Bytes);
            var targetTotal = segments.Where(x => x.Target.Id == target.Id).Sum(x => x.Bytes);
            if (size > SegmentBytes || segments.Count >= SegmentLimit || total + size > ProcessLimit ||
                targetTotal + size > DestinationLimit ||
                (!priority && (segments.Count(x => !x.Priority) >= SegmentLimit / 2 ||
                 segments.Where(x => !x.Priority).Sum(x => x.Bytes) + size > ProcessLimit / 2 ||
                 segments.Where(x => !x.Priority && x.Target.Id == target.Id).Sum(x => x.Bytes) + size > DestinationLimit / 2)) ||
                (diagnostic && (segments.Count(x => x.Diagnostic) >= SegmentLimit / 8 ||
                 segments.Where(x => x.Diagnostic).Sum(x => x.Bytes) + size > ProcessLimit / 8 ||
                 segments.Where(x => x.Diagnostic && x.Target.Id == target.Id).Sum(x => x.Bytes) + size > DestinationLimit / 8)))
                return false;

            var segment = new Segment(target, priority, diagnostic, now, Guid.NewGuid(), events.Length, 0, size);
            var temporary = Path.Combine(directory, $"{segment.Id:N}.pending");
            try
            {
                var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
                if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
                using (var file = new FileStream(temporary, options))
                {
                    file.Write(SHA256.HashData(bytes));
                    file.Write(bytes);
                    file.Flush(flushToDisk: true);
                }
                File.Move(temporary, Path.Combine(directory, segment.Name));
            }
            catch
            {
                File.Delete(temporary);
                throw;
            }
            segments.Add(segment);
            return true;
        }
    }

    public Segment? First(Destination target, bool priority)
    {
        lock (gate)
            return segments.Where(x => x.Target == target && x.Priority == priority)
                .MinBy(x => (x.Diagnostic, x.Created, x.Id));
    }

    public SyslogEvent[] Read(Segment segment)
    {
        using var file = new FileStream(Path.Combine(directory, segment.Name), FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length is < 33 or > SegmentBytes)
            throw new InvalidDataException("Syslog 待发分段长度无效。");
        var bytes = new byte[(int)file.Length];
        file.ReadExactly(bytes);
        if (!CryptographicOperations.FixedTimeEquals(bytes.AsSpan(0, 32), SHA256.HashData(bytes.AsSpan(32))))
            throw new InvalidDataException("Syslog 待发分段校验失败。");
        var events = JsonSerializer.Deserialize(bytes.AsSpan(32), SyslogJsonContext.Default.SyslogEventArray);
        if (events is null || events.Length != segment.Count || Array.Exists(events, e => e is null || e.Priority != segment.Priority))
            throw new InvalidDataException("Syslog 待发分段内容无效。");
        return events;
    }

    public Segment? Advance(Segment segment)
    {
        lock (gate)
        {
            var index = segments.IndexOf(segment);
            if (index < 0) return null;
            if (segment.Offset + 1 >= segment.Count)
            {
                Remove(segment);
                return null;
            }
            var next = segment with { Offset = segment.Offset + 1 };
            File.Move(Path.Combine(directory, segment.Name), Path.Combine(directory, next.Name));
            segments[index] = next;
            return next;
        }
    }

    public void Remove(Segment segment)
    {
        lock (gate)
        {
            File.Delete(Path.Combine(directory, segment.Name));
            segments.Remove(segment);
        }
    }

    public Segment[] Snapshot()
    {
        lock (gate) return [.. segments];
    }
}
