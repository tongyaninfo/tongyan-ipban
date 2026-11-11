using System.Text.Json;

namespace IpBan.Api.Service.Mcp;

public sealed partial class McpBusinessTools
{
    private const string Limit = """{"limit":{"type":"integer","minimum":1,"maximum":100}}""";
    private const string Page = """{"limit":{"type":"integer","minimum":1,"maximum":100},"offset":{"type":"integer","minimum":0,"maximum":100000}}""";
    public static IReadOnlyList<McpToolDefinition> Definitions { get; } = Array.AsReadOnly<McpToolDefinition>(
    [
        Tool("get_overview", "overview", "运行总览", "读取保护状态、登录趋势及来源 IP 排行。", """
            {"range":{"type":"string","enum":["24h","7d","1m"]}}
            """),
        Tool("list_connections", "realtime", "查询当前连接", "分页查看当前 TCP 连接，返回用于下线的连接标识及观察时间。", Page),
        Tool("list_sessions", "realtime", "查询当前登录会话", "分页查看当前 SSH、RDP、WinRM 和 VNC 登录会话。", Page),
        DisconnectTool("disconnect_connection", "断开单条连接", "使用最近查询返回的 connectionId 和 observedAtUtc 断开单条连接。", "connectionId"),
        DisconnectTool("disconnect_session", "断开单个会话", "使用最近查询返回的 sessionId，并将 lastObservedAtUtc 填入 observedAtUtc。", "sessionId"),
        Tool("list_login_events", "security", "查询登录事件", "查看最近登录成功、失败和观察事件。", Limit),
        Tool("list_firewall_actions", "security", "查询防火墙执行记录", "按执行状态查询最近的封禁和解封记录。", """
            {"status":{"type":"string","enum":["Pending","Applied","Failed","Disabled","Removed"]},
            "limit":{"type":"integer","minimum":1,"maximum":100}}
            """),
        Tool("create_ban", "security", "创建限时封禁", "为单个 IP 或 CIDR 创建限时封禁。已有连接使用单独的下线工具处理。", """
            {"sourceAddress":{"type":"string","minLength":1,"maxLength":64},
            "durationSeconds":{"type":"integer","minimum":1,"maximum":604800},
            "reason":{"type":"string","minLength":1,"maxLength":500}}
            """, true, "sourceAddress", "durationSeconds", "reason"),
        Tool("create_permanent_ban", "security", "创建永久封禁", "为单个 IP 或 CIDR 创建不自动到期的封禁，可手动解除。已有连接使用单独的下线工具处理。", """
            {"sourceAddress":{"type":"string","minLength":1,"maxLength":64},
            "reason":{"type":"string","minLength":1,"maxLength":500}}
            """, true, "sourceAddress", "reason"),
        Tool("unban", "security", "解除指定封禁", "根据防火墙执行记录 ID 和来源地址解除对应的有效封禁。", """
            {"actionId":{"type":"string","minLength":1,"maxLength":19},
            "sourceAddress":{"type":"string","minLength":1,"maxLength":64},
            "reason":{"type":"string","minLength":1,"maxLength":500}}
            """, true, "actionId", "sourceAddress", "reason"),
        Tool("list_access_list", "access", "查询黑白名单", "分页读取名单条目及生效、到期时间。", Page),
        Tool("upsert_access_list_entry", "access", "新增或编辑名单", "为 IP 或 CIDR 新增或更新单条名单。必须设置状态和到期时间，编辑时还需明确优先级。", """
            {"id":{"type":"string","minLength":1,"maxLength":19},
            "address":{"type":"string","minLength":1,"maxLength":64},
            "entryType":{"type":"string","enum":["Allow","Deny"]},
            "priority":{"type":"integer","minimum":0,"maximum":10000},
            "status":{"type":"string","enum":["Active","Inactive"]},
            "reason":{"type":"string","minLength":1,"maxLength":500},
            "effectiveAtUtc":{"type":"string","format":"date-time"},
            "expiresAtUtc":{"type":"string","format":"date-time"}}
            """, true, "address", "entryType", "reason", "status", "expiresAtUtc"),
        Tool("list_ban_policies", "access", "查询自动封禁策略", "分页读取自动封禁策略和当前版本。", Page),
        Tool("update_ban_policy", "access", "编辑自动封禁策略", "按记录 ID 和版本更新策略配置，保持现有启停状态。已启用的策略会按既有规则自动封禁和处置已有连接。", """
            {"id":{"type":"string","minLength":1,"maxLength":19},
            "version":{"type":"integer","minimum":1,"maximum":2147483647},
            "name":{"type":"string","minLength":1,"maxLength":128},
            "threshold":{"type":"integer","minimum":1,"maximum":2147483647},
            "windowSeconds":{"type":"integer","minimum":1,"maximum":2147483647},
            "observeSeconds":{"type":"integer","minimum":0,"maximum":2147483647},
            "cooldownSeconds":{"type":"integer","minimum":0,"maximum":2147483647},
            "banDurationSeconds":{"type":"integer","minimum":-1,"maximum":2147483647},
            "action":{"type":"string","enum":["Observe","Ban"]},
            "protocol":{"type":"string","enum":["ALL","Ssh","Vnc","Rdp","OpenSsh","WinRm"]},
            "description":{"type":"string","maxLength":500},
            "reason":{"type":"string","minLength":1,"maxLength":500}}
            """, true, "id", "version", "name", "threshold", "windowSeconds", "observeSeconds",
            "cooldownSeconds", "banDurationSeconds", "action", "reason"),
        Tool("set_ban_policy_enabled", "access", "启停自动封禁策略", "按记录 ID 和版本启停已有策略。启用后会按既有规则自动封禁和处置已有连接。", """
            {"id":{"type":"string","minLength":1,"maxLength":19},
            "version":{"type":"integer","minimum":1,"maximum":2147483647},
            "enabled":{"type":"boolean"},
            "reason":{"type":"string","minLength":1,"maxLength":500}}
            """, true, "id", "version", "enabled", "reason"),
        Tool("list_log_files", "diagnostics", "查询日志文件元数据", "分页查看日志文件名、大小、时间及压缩状态。", Page),
        Tool("list_backups", "diagnostics", "查询备份元数据", "查看最近备份的类型、大小、时间及状态。", Limit),
        Tool("list_certificates", "diagnostics", "查询证书元数据", "分页查看证书主题、指纹、有效期及启用状态。", Page),
    ]);

    private static McpToolDefinition DisconnectTool(string name, string title, string description, string idField) =>
        Tool(name, "realtime", title, description, $$"""
            {"{{idField}}":{"type":"string","minLength":1,"maxLength":256},
            "observedAtUtc":{"type":"string","format":"date-time"},
            "reason":{"type":"string","minLength":1,"maxLength":500}
            }
            """, true, idField, "observedAtUtc", "reason");

    private static McpToolDefinition Tool(string name, string group, string title, string description,
        string properties, bool isWrite = false, params string[] required)
    {
        // 目录及执行参数由同一份 schema 定义，避免权限页、发现结果和运行校验各自漂移。
        var fields = string.Join(',', required.Select(field => $"\"{field}\""));
        using var schema = JsonDocument.Parse(
            $$"""{"type":"object","additionalProperties":false,"properties":{{properties}},"required":[{{fields}}]}""");
        return new McpToolDefinition(name, group, title, description, isWrite, isWrite, schema.RootElement.Clone());
    }
}
