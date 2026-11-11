using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace IpBan.Shared.Logging.Syslog;

public static class SyslogWire
{
    // RFC 5424 的 PRI 必须包含设施码，IPBan 统一使用 local0。
    private const int Local0Facility = 16;
    private static readonly byte[] Bom = [0xef, 0xbb, 0xbf];

    public static byte[] Format(SyslogEvent entry, int maxBytes = 8192) =>
        Format(entry, maxBytes, out _);

    internal static byte[] Format(SyslogEvent entry, int maxBytes, out bool truncated)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxBytes, 480);
        var severity = (int)entry.Severity;
        ArgumentOutOfRangeException.ThrowIfNegative(severity);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(severity, 7);

        var timestamp = entry.OccurredAtUtc.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);
        var processId = entry.ProcessId > 0 ? entry.ProcessId.ToString(CultureInfo.InvariantCulture) : "-";
        var header = Encoding.ASCII.GetBytes(FormattableString.Invariant(
            $"<{Local0Facility * 8 + severity}>1 {timestamp} {Hostname(entry.ComputerName)} {HeaderField(entry.AppName, 48)} {processId} {HeaderField(entry.EventType, 32)} - "));

        var budget = maxBytes - header.Length - Bom.Length;
        var body = FormatBodyWithinBudget(entry, budget, out truncated);
        var message = new byte[header.Length + Bom.Length + body.Length];
        header.CopyTo(message, 0);
        Bom.CopyTo(message, header.Length);
        body.CopyTo(message, header.Length + Bom.Length);
        return message;
    }

    private static string Hostname(string computerName)
    {
        var input = string.IsNullOrEmpty(computerName) ? "unknown" : computerName;
        if (input.Length <= 248 && input.All(static c => c is >= '!' and <= '~' and not '~'))
            return $"syslog-{input}";

        // 转义标记本身也参与编码，同一主机在各协议中始终使用同一个报文头名称。
        var encoded = new StringBuilder("syslog-");
        foreach (var rune in input.EnumerateRunes())
        {
            var value = rune.Value;
            if (value is >= '!' and <= '~' and not '~')
                encoded.Append((char)value);
            else
                encoded.Append('~').Append(value.ToString("x6", CultureInfo.InvariantCulture));

            if (encoded.Length > 220)
            {
                var hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(input)).AsSpan(0, 12));
                return encoded.Append("~h").Append(hash).ToString();
            }
        }

        return encoded.ToString();
    }

    private static string HeaderField(string value, int maxLength)
    {
        if (string.IsNullOrEmpty(value) || !value.All(static c => c is >= '!' and <= '~'))
            return "-";
        if (value.Length <= maxLength)
            return value;

        var hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(value)).AsSpan(0, 5));
        return string.Concat(value.AsSpan(0, maxLength - hash.Length - 1), "-", hash);
    }

    private static byte[] FormatBodyWithinBudget(SyslogEvent entry, int budget, out bool truncated)
    {
        var message = entry.Message.AsSpan();
        if (message.Length <= budget)
        {
            var full = WriteBody(entry, message, BodyFields.Full, false);
            if (full.Length <= budget)
            {
                truncated = false;
                return full;
            }
        }

        // UDP 的报文上限可能小于完整元数据。逐步缩小字段集合，并保证结果始终是合法 JSON。
        truncated = true;
        foreach (var fields in new[] { BodyFields.Compact, BodyFields.Essential, BodyFields.IdOnly })
        {
            var best = WriteBody(entry, ReadOnlySpan<char>.Empty, fields, true);
            if (best.Length > budget)
                continue;
            if (fields is BodyFields.IdOnly)
                return best;

            var low = 1;
            var high = Math.Min(message.Length, budget);
            while (low <= high)
            {
                var length = low + (high - low) / 2;
                var runeBoundary = length;
                if (length < message.Length && char.IsHighSurrogate(message[length - 1]) && char.IsLowSurrogate(message[length]))
                    runeBoundary--;

                var candidate = WriteBody(entry, message[..runeBoundary], fields, true);
                if (candidate.Length <= budget)
                {
                    best = candidate;
                    low = length + 1;
                }
                else
                {
                    high = length - 1;
                }
            }

            return best;
        }

        throw new ArgumentException("Syslog 报文头和事件标识超出允许的报文大小。", nameof(entry));
    }

    private static byte[] WriteBody(SyslogEvent entry, ReadOnlySpan<char> message, BodyFields fields, bool truncated)
    {
        var output = new ArrayBufferWriter<byte>();
        using var writer = new Utf8JsonWriter(output, new JsonWriterOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
        writer.WriteStartObject();
        writer.WriteString("eventUid", entry.EventUid);
        if (fields is not BodyFields.IdOnly)
        {
            writer.WriteNumber("syslogSeverity", (int)entry.Severity);
            writer.WriteString("deliveryPriority", entry.Priority ? "P0" : "normal");
            writer.WriteString("message", message);
        }

        if (fields is BodyFields.Full or BodyFields.Compact)
        {
            writer.WriteNumber("schemaVersion", 1);
            writer.WriteString("eventType", entry.EventType);
            writer.WriteString("sourceProcess", entry.SourceProcess);
            WriteOptional(writer, "result", entry.Result);
            WriteOptional(writer, "remoteIp", entry.RemoteIp);
        }

        if (fields is BodyFields.Full)
        {
            writer.WriteString("occurredAtUtc", entry.OccurredAtUtc.ToUniversalTime());
            writer.WriteString("computerName", entry.ComputerName);
            writer.WriteString("module", entry.AppName);
            WriteOptional(writer, "category", entry.Category);
            WriteOptional(writer, "runtimeLevel", entry.RuntimeLevel);
            WriteOptional(writer, "traceId", entry.TraceId);
            WriteOptional(writer, "sourceId", entry.SourceId);
            WriteOptional(writer, "protocol", entry.Protocol);
            WriteOptional(writer, "actor", entry.Actor);
        }

        if (truncated)
            writer.WriteBoolean("truncated", true);

        writer.WriteEndObject();
        writer.Flush();
        return output.WrittenSpan.ToArray();
    }

    private static void WriteOptional(Utf8JsonWriter writer, string name, string? value)
    {
        if (!string.IsNullOrEmpty(value))
            writer.WriteString(name, value);
    }

    private enum BodyFields { Full, Compact, Essential, IdOnly }
}
