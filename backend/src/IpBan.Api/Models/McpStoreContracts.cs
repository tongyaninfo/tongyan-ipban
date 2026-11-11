using System.Text.Json.Serialization;

namespace IpBan.Api.Models;

public sealed record McpSettings(bool Enabled, int AuditRetentionDays);

public sealed record McpApiKey(
    [property: JsonNumberHandling(JsonNumberHandling.WriteAsString)] long Id,
    string Name,
    string Prefix,
    string Mode,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? ExpiresAtUtc,
    DateTimeOffset? RevokedAtUtc,
    string[] Scopes);

public sealed record McpCreatedKey(McpApiKey Key, string Secret)
{
    public override string ToString() => $"McpCreatedKey {{ KeyId = {Key.Id} }}";
}

public sealed record McpCallStart(
    McpApiKey? Key,
    string TraceId,
    string? RemoteIp,
    string? Method,
    string? Tool,
    string? RequestHeaders,
    string? RequestBody,
    string Path = "/mcp");

public sealed record McpCallFilter(
    DateTimeOffset? FromUtc,
    DateTimeOffset? ToUtc,
    long? KeyId,
    string? Tool,
    string? Status,
    int Page = 1,
    int PageSize = 20);

public sealed record McpCallSummary(
    [property: JsonNumberHandling(JsonNumberHandling.WriteAsString)] long Id,
    DateTimeOffset OccurredAtUtc,
    [property: JsonNumberHandling(JsonNumberHandling.WriteAsString)] long? KeyId,
    string? KeyName,
    string? KeyPrefix,
    string TraceId,
    string? RemoteIp,
    string? Method,
    string? Tool,
    string Status,
    int? HttpStatus,
    long? DurationMs);

public sealed record McpCallDetail(
    McpCallSummary Call,
    string Path,
    string? RequestHeaders,
    string? RequestBody,
    string? ResponseHeaders,
    string? ResponseBody);

public sealed record McpCallPage(McpCallSummary[] Items, long Total);
