using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace IpBan.Api.Service.Mcp;

internal static partial class McpAuditPayload
{
    private const string CredentialPresent = "[凭证已提供]";

    public static string Headers(IHeaderDictionary headers, string? secret)
    {
        using var bytes = new MemoryStream();
        using var writer = new Utf8JsonWriter(bytes);
        writer.WriteStartObject();
        foreach (var header in headers)
        {
            writer.WriteStartArray(Value(header.Key, secret));
            foreach (var value in header.Value)
                writer.WriteStringValue(IsCredential(header.Key) ? CredentialPresent : Value(value ?? string.Empty, secret));
            writer.WriteEndArray();
        }
        writer.WriteEndObject();
        writer.Flush();
        return Encoding.UTF8.GetString(bytes.GetBuffer(), 0, (int)bytes.Length);
    }

    public static string Json(JsonElement value, string? secret)
    {
        using var bytes = new MemoryStream();
        using var writer = new Utf8JsonWriter(bytes);
        WriteJson(writer, value, secret);
        writer.Flush();
        return Encoding.UTF8.GetString(bytes.GetBuffer(), 0, (int)bytes.Length);
    }

    public static string Response(string payload, string? secret)
    {
        if (payload.Length == 0) return payload;
        if (TryParse(payload) is { } document)
        {
            using (document) return Json(document.RootElement, secret);
        }

        // Streamable HTTP 可以按 SSE 帧返回 JSON-RPC，保留实际帧及业务数据。
        return string.Join('\n', payload.Split('\n').Select(line =>
        {
            if (!line.StartsWith("data:", StringComparison.Ordinal) || TryParse(line[5..]) is not { } frame)
                return Value(line, secret);
            using (frame) return "data: " + Json(frame.RootElement, secret);
        }));
    }

    public static bool HasProtocolError(string payload)
    {
        if (TryParse(payload) is { } document)
        {
            using (document) return IsError(document.RootElement);
        }

        foreach (var line in payload.Split('\n'))
        {
            if (!line.StartsWith("data:", StringComparison.Ordinal) || TryParse(line[5..]) is not { } frame) continue;
            using (frame) if (IsError(frame.RootElement)) return true;
        }
        return false;
    }

    public static string Value(string value, string? secret)
    {
        if (!string.IsNullOrEmpty(secret)) value = value.Replace(secret, CredentialPresent, StringComparison.Ordinal);
        return KeyPattern().Replace(value, CredentialPresent);
    }

    [GeneratedRegex(@"ipban_[0-9a-f]{64}", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex KeyPattern();

    private static bool IsError(JsonElement value) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty("error", out _);

    private static JsonDocument? TryParse(string input)
    {
        try { return JsonDocument.Parse(input); }
        catch (JsonException) { return null; }
    }

    private static void WriteJson(Utf8JsonWriter writer, JsonElement value, string? secret)
    {
        switch (value.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in value.EnumerateObject())
                {
                    writer.WritePropertyName(Value(property.Name, secret));
                    if (IsCredential(property.Name)) writer.WriteStringValue(CredentialPresent);
                    else WriteJson(writer, property.Value, secret);
                }
                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in value.EnumerateArray()) WriteJson(writer, item, secret);
                writer.WriteEndArray();
                break;
            case JsonValueKind.String:
                writer.WriteStringValue(Value(value.GetString()!, secret));
                break;
            default:
                value.WriteTo(writer);
                break;
        }
    }

    private static bool IsCredential(string name)
    {
        var normalized = name.Replace("-", string.Empty, StringComparison.Ordinal)
            .Replace("_", string.Empty, StringComparison.Ordinal);
        return normalized.Contains("authorization", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("cookie", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("apikey", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("password", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("secret", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("token", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("privatekey", StringComparison.OrdinalIgnoreCase)
            || normalized.Equals("mcpsessionid", StringComparison.OrdinalIgnoreCase);
    }
}
