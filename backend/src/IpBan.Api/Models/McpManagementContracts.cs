namespace IpBan.Api.Models;

internal sealed record McpSettingsRequest(bool? Enabled, int? AuditRetentionDays, bool ConfirmShorter);

internal sealed record McpCreateKeyRequest(string? Name, string? Mode, string[]? Scopes, DateTimeOffset? ExpiresAtUtc);

internal sealed record McpToolView(string Id, string Group, string Label, string Description, bool IsWrite, bool IsDangerous);

internal sealed record McpKeyView(string Id, string Name, string Prefix, string Mode, string[] Scopes,
    DateTimeOffset CreatedAtUtc, DateTimeOffset? ExpiresAtUtc, DateTimeOffset? RevokedAtUtc);

internal sealed record McpSecretView(string Secret);

internal sealed record McpCreatedKeyView(McpKeyView Key, string Secret);

internal sealed record McpAuditPageView(McpAuditView[] Items, long Total);

internal sealed record McpAuditView(string Id, DateTimeOffset OccurredAtUtc, string? KeyId, string? KeyName, string? KeyPrefix,
    string? RemoteIp, string? Method, string? Tool, string Status, int? HttpStatus, long? DurationMs, string TraceId)
{
    public string? Path { get; init; }
    public string? RequestHeaders { get; init; }
    public string? RequestBody { get; init; }
    public string? ResponseHeaders { get; init; }
    public string? ResponseBody { get; init; }
}
