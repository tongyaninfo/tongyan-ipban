using System.Text.Json;

namespace IpBan.Api.Service.Mcp;

public sealed record McpToolDefinition(string Name, string Group, string Title, string Description,
    bool IsWrite, bool IsDangerous, JsonElement InputSchema);

public sealed record McpBusinessResult(bool Success, string Code, string Message, JsonElement? Data);
