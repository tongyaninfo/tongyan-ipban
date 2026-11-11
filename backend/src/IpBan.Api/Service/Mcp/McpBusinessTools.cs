using System.Data;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using IpBan.Api.Service.impl;
using IpBan.Shared.Logging;
using IpBan.Shared.Models;
using IpBan.Shared.Service;
using Microsoft.Data.Sqlite;

namespace IpBan.Api.Service.Mcp;

/// <summary>将已授权的 MCP 调用交给现有管理数据和本机 Agent，保持业务返回的执行语义。</summary>
public sealed partial class McpBusinessTools(
    SqliteAdminStore store,
    IAgentIpcClient agent,
    FileLogStore logs,
    IConfiguration configuration,
    IHttpContextAccessor? contextAccessor = null)
{
    private const int DefaultPageSize = 50;
    private static readonly McpBusinessJsonContext Json = McpBusinessJsonContext.Default;
    private readonly HashSet<int> _managementPorts = ReadManagementPorts(configuration);

    public Task<McpBusinessResult> InvokeAsync(string name, JsonElement arguments, string actor, CancellationToken ct) =>
        InvokeAsync(name, arguments, actor, null, ct);

    public async Task<McpBusinessResult> InvokeAsync(string name, JsonElement arguments, string actor,
        Func<CancellationToken, Task<bool>>? authorizeWrite, CancellationToken ct)
    {
        var tool = Definitions.FirstOrDefault(item => item.Name == name);
        if (tool is null)
            return Fail("UNKNOWN_TOOL", "工具不存在。");
        if (ValidateArguments(tool.InputSchema, arguments) is { } error)
            return error;

        var limit = Int(arguments, "limit", DefaultPageSize);
        var offset = Int(arguments, "offset", 0);
        try
        {
            return name switch
            {
                "get_overview" => await GetOverviewAsync(String(arguments, "range"), ct).ConfigureAwait(false),
                "list_connections" => await ListConnectionsAsync(limit, offset, ct).ConfigureAwait(false),
                "list_sessions" => await ListSessionsAsync(limit, offset, ct).ConfigureAwait(false),
                "disconnect_connection" => await DisconnectAsync(arguments, false, authorizeWrite, ct).ConfigureAwait(false),
                "disconnect_session" => await DisconnectAsync(arguments, true, authorizeWrite, ct).ConfigureAwait(false),
                "list_login_events" => await ListLoginEventsAsync(limit, ct).ConfigureAwait(false),
                "list_firewall_actions" => Ok((await store.ListFirewallActionsAsync(String(arguments, "status"), limit, ct).ConfigureAwait(false))
                    .Select(item => item with { ErrorMessage = null }).ToArray(), Json.FirewallActionContractArray),
                "create_ban" => await CreateBanAsync(arguments, Int(arguments, "durationSeconds", 0), actor, authorizeWrite, ct).ConfigureAwait(false),
                "create_permanent_ban" => await CreateBanAsync(arguments, ManualBanDuration.Permanent, actor, authorizeWrite, ct).ConfigureAwait(false),
                "unban" => await UnbanAsync(arguments, actor, authorizeWrite, ct).ConfigureAwait(false),
                "list_access_list" => Ok((await store.ListAccessListPageAsync(limit, offset, ct).ConfigureAwait(false))
                    .Select(McpAccessListEntry.From).ToArray(), Json.McpAccessListEntryArray),
                "upsert_access_list_entry" => await UpsertAccessListAsync(arguments, actor, authorizeWrite, ct).ConfigureAwait(false),
                "list_ban_policies" => Ok((await store.ListPolicyPageAsync(limit, offset, ct).ConfigureAwait(false))
                    .Select(McpBanPolicy.From).ToArray(), Json.McpBanPolicyArray),
                "update_ban_policy" => await UpdatePolicyAsync(arguments, actor, false, authorizeWrite, ct).ConfigureAwait(false),
                "set_ban_policy_enabled" => await UpdatePolicyAsync(arguments, actor, true, authorizeWrite, ct).ConfigureAwait(false),
                "list_log_files" => Ok(logs.ListFiles().Skip(offset).Take(limit)
                    .Select(item => new McpLogFile(item.Name, item.SizeBytes, item.LastWriteTimeUtc, item.Compressed))
                    .ToArray(), Json.McpLogFileArray),
                "list_backups" => Ok((await store.ListBackupsAsync(limit, ct).ConfigureAwait(false))
                    .Select(item => new McpBackup(McpIdentifier.Format(item.Id), item.BackupKind, item.SizeBytes,
                        item.Sha256, item.CreatedAtUtc, item.Status)).ToArray(), Json.McpBackupArray),
                "list_certificates" => Ok((await store.ListCertificatesAsync(ct).ConfigureAwait(false)).Skip(offset).Take(limit)
                    .Select(item => new McpCertificate(McpIdentifier.Format(item.Id), item.Subject, item.Issuer,
                        item.Thumbprint, item.NotBeforeUtc, item.NotAfterUtc, item.Active)).ToArray(), Json.McpCertificateArray),
                _ => Fail("UNKNOWN_TOOL", "工具不存在。")
            };
        }
        catch (DBConcurrencyException)
        {
            return Fail("STALE_RECORD", "记录已变更或不存在。请重新查询后再操作。");
        }
        catch (SqliteException exception) when (exception.SqliteErrorCode == 19)
        {
            return Fail("CONFLICT", "该条目与已有记录冲突。");
        }
    }

    private async Task<McpBusinessResult> GetOverviewAsync(string? range, CancellationToken ct)
    {
        var connections = await ReadVisibleConnectionsAsync(ct).ConfigureAwait(false);
        int? sessions = connections.Data is null
            ? null : (await ReadSessionsAsync(connections.Data, ct).ConfigureAwait(false)).Count;
        var firewall = await agent.ProbeFirewallAsync(ct).ConfigureAwait(false);
        var overview = await store.GetOverviewAsync(connections.Data?.LongLength ?? 0, sessions ?? 0,
            firewall.Data?.Provider ?? "not-probed", firewall.Data?.Status ?? FirewallStatus.Unsupported,
            range, ct).ConfigureAwait(false);
        // 总览权限只返回聚合值。原始登录事件需要单独授权，实时采集失败用 null 区分真实的零。
        return Ok(new McpOverview(overview.CheckedAtUtc, overview.TrendRange,
            overview.Ready && connections.Success && firewall.Success, overview.FirewallProvider, overview.FirewallStatus,
            connections.Data?.LongLength, sessions, overview.TodayLoginSuccess, overview.TodayLoginFailures,
            overview.TodayObserveOnly, overview.ObserveOnlyWithoutIp, overview.ActiveBans,
            overview.Trend, overview.TopSourceIps), Json.McpOverview);
    }

    private async Task<McpBusinessResult> ListConnectionsAsync(int limit, int offset, CancellationToken ct)
    {
        var connections = await ReadVisibleConnectionsAsync(ct).ConfigureAwait(false);
        if (!connections.Success || connections.Data is null)
            return Fail(connections.Code, "当前连接查询失败。");

        return Ok(connections.Data.Skip(offset).Take(limit).Select(connection => new McpConnection(
            CurrentSessionProjector.BuildSessionId(connection), connection.Protocol, connection.State,
            connection.RemoteIp, connection.RemotePort, connection.LocalIp, connection.LocalPort, connection.ProcessId,
            McpIdentifier.FileName(connection.ProcessName), connection.ObservedAtUtc,
            IsDisconnectable(connection))).ToArray(), Json.McpConnectionArray);
    }

    private async Task<McpBusinessResult> ListSessionsAsync(int limit, int offset, CancellationToken ct)
    {
        var connections = await ReadVisibleConnectionsAsync(ct).ConfigureAwait(false);
        if (!connections.Success || connections.Data is null)
            return Fail(connections.Code, "当前登录会话查询失败。");

        var sessions = await ReadSessionsAsync(connections.Data, ct).ConfigureAwait(false);
        var disconnectable = connections.Data.Where(IsDisconnectable)
            .Select(CurrentSessionProjector.BuildSessionId).ToHashSet(StringComparer.Ordinal);
        return Ok(sessions.Skip(offset).Take(limit).Select(session => session with
        {
            ProcessName = McpIdentifier.FileName(session.ProcessName),
            CanDisconnect = session.CanDisconnect && disconnectable.Contains(session.SessionId)
        }).ToArray(), Json.LoginSessionContractArray);
    }

    private async Task<ApiResult<ConnectionSnapshotContract[]>> ReadVisibleConnectionsAsync(CancellationToken ct)
    {
        var result = await agent.ListConnectionsAsync(ct).ConfigureAwait(false);
        return result.Success && result.Data is { } connections
            ? result with { Data = connections.Where(item => !IsManagementConnection(item)).ToArray() }
            : result;
    }

    private async Task<IReadOnlyList<LoginSessionContract>> ReadSessionsAsync(ConnectionSnapshotContract[] connections,
        CancellationToken ct)
    {
        var events = await agent.ListLoginEventsAsync(1000, ct).ConfigureAwait(false);
        return CurrentSessionProjector.Project(connections, events.Success ? events.Data ?? [] : []);
    }

    private async Task<McpBusinessResult> ListLoginEventsAsync(int limit, CancellationToken ct)
    {
        var result = await agent.ListLoginEventsAsync(limit, ct).ConfigureAwait(false);
        return result.Success && result.Data is { } events
            ? Ok(events.Take(limit).Select(McpLoginEvent.From).ToArray(), Json.McpLoginEventArray)
            : Fail(result.Code, "登录事件查询失败。");
    }

    private async Task<McpBusinessResult> DisconnectAsync(JsonElement args, bool isSession,
        Func<CancellationToken, Task<bool>>? authorizeWrite, CancellationToken ct)
    {
        var observedAt = ReadDate(args, "observedAtUtc");
        var now = DateTimeOffset.UtcNow;
        // 短时有效的标识和实时快照共同限定操作，避免使用旧连接信息下线不同连接。
        if (observedAt < now.AddSeconds(-60) || observedAt > now.AddSeconds(5))
            return Fail("STALE_CONNECTION", "连接快照已过期，请重新查询。");

        var connections = await ReadVisibleConnectionsAsync(ct).ConfigureAwait(false);
        if (!connections.Success || connections.Data is null)
            return Fail(connections.Code, "当前连接查询失败。");

        var id = String(args, isSession ? "sessionId" : "connectionId");
        var targets = connections.Data.Where(item => IsDisconnectable(item)
            && CurrentSessionProjector.BuildSessionId(item).Equals(id, StringComparison.Ordinal)).Take(2).ToArray();
        if (targets.Length != 1)
            return Fail("CONNECTION_NOT_FOUND", "目标连接已不存在或不能下线。");
        var target = targets[0];
        if (isSession)
        {
            var sessions = await ReadSessionsAsync([target], ct).ConfigureAwait(false);
            if (sessions.Count != 1 || !sessions[0].CanDisconnect)
                return Fail("SESSION_NOT_FOUND", "目标登录会话已不存在或不能下线。");
        }

        if (await CheckWriteAccessAsync(authorizeWrite, ct).ConfigureAwait(false) is { } denied)
            return denied;
        var result = await agent.DisconnectExactAsync(target, ct).ConfigureAwait(false);
        return FromAgent(result, result.Data is { } data ? data with { Error = null } : null,
            Json.ConnectionTerminationContract, "连接下线请求失败。");
    }

    private async Task<McpBusinessResult> CreateBanAsync(JsonElement args, int durationSeconds, string actor,
        Func<CancellationToken, Task<bool>>? authorizeWrite, CancellationToken ct)
    {
        var source = ParseAddress(String(args, "sourceAddress"));
        if (source is null)
            return Fail("INVALID_SOURCE_ADDRESS", "请提供有效的单个 IP 或 CIDR，网段不能覆盖全部地址。");

        if (await CheckWriteAccessAsync(authorizeWrite, ct).ConfigureAwait(false) is { } denied)
            return denied;
        var context = contextAccessor?.HttpContext;
        await AuditMcpBanAsync(context, "mcp.ban.create.request", source, actor, "requested", true, ct).ConfigureAwait(false);
        // 封禁和已有连接下线是两个独立授权，任何封禁调用均不隐式下线连接。
        var result = await agent.BanAsync(source, durationSeconds, false, context?.TraceIdentifier, ct).ConfigureAwait(false);
        if (result.Data is null)
            await AuditMcpBanAsync(context, "mcp.ban.create", source, actor, result.Code, false, CancellationToken.None).ConfigureAwait(false);
        var safe = result.Data is { } data
            ? data with
            {
                FirewallAction = data.FirewallAction with { ErrorMessage = null },
                ExistingConnectionTermination = data.ExistingConnectionTermination with { Error = null }
            }
            : null;
        return FromAgent(result, safe, Json.ManualBanResult, "封禁未确认生效。");
    }

    private async Task<McpBusinessResult> UnbanAsync(JsonElement args, string actor,
        Func<CancellationToken, Task<bool>>? authorizeWrite, CancellationToken ct)
    {
        var id = ReadId(args, "actionId");
        var address = String(args, "sourceAddress");
        if (id is null || address is null)
            return Fail("INVALID_BAN_ACTION", "请提供有效的执行记录 ID 和来源 IP 或 CIDR。");

        if (await CheckWriteAccessAsync(authorizeWrite, ct).ConfigureAwait(false) is { } denied)
            return denied;
        var context = contextAccessor?.HttpContext;
        await AuditMcpBanAsync(context, "mcp.ban.unban.request", address, actor, "requested", true, ct).ConfigureAwait(false);
        // Agent 原子核对地址及执行代次，允许解除历史上已经生效的宽网段规则。
        var result = await agent.UnbanAsync(address, id.Value, context?.TraceIdentifier, ct).ConfigureAwait(false);
        if (result.Data is null)
            await AuditMcpBanAsync(context, "mcp.ban.unban", address, actor, result.Code, false, CancellationToken.None).ConfigureAwait(false);
        return FromAgent(result, result.Data is { } data ? data with { ErrorMessage = null } : null,
            Json.FirewallActionResult, "解封未确认生效。");
    }

    private Task AuditMcpBanAsync(HttpContext? context, string action, string target, string actor, string result, bool success,
        CancellationToken cancellationToken) => context is null ? Task.CompletedTask
        : store.AppendAuditAsync(action, "firewall", target, null, context.Connection.RemoteIpAddress?.ToString(), success,
            actor, context.TraceIdentifier, result: result, cancellationToken: cancellationToken);

    private async Task<McpBusinessResult> UpsertAccessListAsync(JsonElement args, string actor,
        Func<CancellationToken, Task<bool>>? authorizeWrite, CancellationToken ct)
    {
        var id = ReadId(args, "id");
        if (String(args, "id") is not null && id is null)
            return Fail("INVALID_ACCESS_LIST_ENTRY", "名单 ID 必须为正整数的十进制字符串。");
        if (id is not null && !args.TryGetProperty("priority", out _))
            return Fail("INVALID_ACCESS_LIST_ENTRY", "编辑名单时必须提供优先级。");

        var address = ParseAddress(String(args, "address"));
        var start = ReadDate(args, "effectiveAtUtc");
        var expires = ReadDate(args, "expiresAtUtc");
        var now = DateTimeOffset.UtcNow;
        if (address is null || expires <= now || (start is { } effective && expires <= effective))
            return Fail("INVALID_ACCESS_LIST_ENTRY", "请检查 IP/CIDR，且到期时间必须晚于当前时间和生效时间。");

        var request = new UpsertAccessListEntryRequest(address, String(args, "entryType")!,
            Reason: String(args, "reason"), Priority: Int(args, "priority", 100), Status: String(args, "status")!,
            CreatedBy: actor, EffectiveAtUtc: start, ExpiresAtUtc: expires);
        if (await CheckWriteAccessAsync(authorizeWrite, ct).ConfigureAwait(false) is { } denied)
            return denied;
        var entry = await store.UpsertAccessListForMcpAsync(id, request, actor, ct).ConfigureAwait(false);
        return Ok(McpAccessListEntry.From(entry), Json.McpAccessListEntry);
    }

    private async Task<McpBusinessResult> UpdatePolicyAsync(JsonElement args, string actor, bool toggleOnly,
        Func<CancellationToken, Task<bool>>? authorizeWrite, CancellationToken ct)
    {
        var id = ReadId(args, "id");
        if (id is null)
            return Fail("INVALID_BAN_POLICY", "策略 ID 必须为正整数的十进制字符串。");

        var previous = await store.FindPolicyAsync(id.Value, ct).ConfigureAwait(false);
        if (previous is null)
            return Fail("BAN_POLICY_NOT_FOUND", "自动封禁策略不存在。");
        var version = Int(args, "version", 0);
        if (previous.Version != version)
            return Fail("STALE_RECORD", "策略版本已变更，请重新查询。");

        var request = toggleOnly
            ? new UpsertBanPolicyRequest(previous.Name, args.GetProperty("enabled").GetBoolean(), previous.Threshold,
                previous.WindowSeconds, previous.ObserveSeconds, previous.CooldownSeconds, previous.BanDurationSeconds,
                previous.Action, previous.Protocol, previous.Description)
            : new UpsertBanPolicyRequest(String(args, "name")!, previous.Enabled,
                Int(args, "threshold", 0), Int(args, "windowSeconds", 0), Int(args, "observeSeconds", 0),
                Int(args, "cooldownSeconds", 0), Int(args, "banDurationSeconds", 0), String(args, "action")!,
                String(args, "protocol") ?? previous.Protocol, String(args, "description") ?? previous.Description);
        if (BanPolicyRequestValidator.Validate(request) is { } failure)
            return Fail(failure.Code, failure.Message);

        if (await CheckWriteAccessAsync(authorizeWrite, ct).ConfigureAwait(false) is { } denied)
            return denied;
        var policy = await store.UpdatePolicyForMcpAsync(id.Value, version, request, actor, ct).ConfigureAwait(false);
        return Ok(McpBanPolicy.From(policy), Json.McpBanPolicy);
    }

    private bool IsManagementConnection(ConnectionSnapshotContract connection) =>
        (connection.LocalPort is { } port && _managementPorts.Contains(port))
        || connection.ProcessName?.Contains("IpBan.", StringComparison.OrdinalIgnoreCase) == true;

    private static bool IsDisconnectable(ConnectionSnapshotContract item) =>
        item.Protocol.Equals("tcp", StringComparison.OrdinalIgnoreCase)
        && item.State.Equals("ESTAB", StringComparison.OrdinalIgnoreCase)
        && item.LocalPort is > 0 && item.RemotePort is > 0 && item.ProcessId is > 0
        && !string.IsNullOrWhiteSpace(item.LocalIp) && !string.IsNullOrWhiteSpace(item.RemoteIp);

    private static HashSet<int> ReadManagementPorts(IConfiguration config)
    {
        var result = new HashSet<int>
        {
            int.TryParse(config["Management:HttpPort"], out var httpPort) ? httpPort : 5180,
            int.TryParse(config["Management:HttpsPort"], out var httpsPort) ? httpsPort : 8443
        };
        foreach (var address in (config["ASPNETCORE_URLS"] ?? config["urls"] ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            // Kestrel 允许通配 host。只取其明确端口作为保护范围。
            if (int.TryParse(address.AsSpan(address.LastIndexOf(':') + 1), NumberStyles.None,
                CultureInfo.InvariantCulture, out var port) && port is > 0 and <= 65535)
                result.Add(port);
            else if (Uri.TryCreate(address, UriKind.Absolute, out var uri) && uri.Port > 0)
                result.Add(uri.Port);
            else if (address.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                result.Add(443);
            else if (address.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                result.Add(80);
        }
        return result;
    }

    private static McpBusinessResult Ok<T>(T value, JsonTypeInfo<T> typeInfo) =>
        new(true, "OK", "操作成功。", JsonSerializer.SerializeToElement(value, typeInfo));

    private static McpBusinessResult Fail(string code, string message) => new(false, code, message, null);

    private static async Task<McpBusinessResult?> CheckWriteAccessAsync(Func<CancellationToken, Task<bool>>? authorizeWrite,
        CancellationToken cancellationToken)
    {
        // 准备数据可能消耗一个或多个 IPC 往返，最后一次校验必须紧邻实际写入。
        return authorizeWrite is null || await authorizeWrite(cancellationToken).ConfigureAwait(false)
            ? null : Fail("MCP_ACCESS_CHANGED", "MCP 服务或 API Key 状态已变化。");
    }

    private static McpBusinessResult FromAgent<T>(ApiResult<T> result, T? safe, JsonTypeInfo<T> typeInfo, string fallback)
        where T : class =>
        new(result.Success && safe is not null, result.Success && safe is null ? "AGENT_IPC_INVALID_RESPONSE" : result.Code,
            result.Success && safe is not null ? "操作成功。" : fallback,
            safe is null ? null : JsonSerializer.SerializeToElement(safe, typeInfo));

    private static McpBusinessResult? ValidateArguments(JsonElement schema, JsonElement arguments)
    {
        if (arguments.ValueKind is not (JsonValueKind.Object or JsonValueKind.Undefined))
            return Fail("INVALID_ARGUMENTS", "工具参数必须为 JSON 对象。");
        var fields = schema.GetProperty("properties");
        var supplied = new HashSet<string>(StringComparer.Ordinal);
        if (arguments.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in arguments.EnumerateObject())
            {
                if (!supplied.Add(property.Name) || !fields.TryGetProperty(property.Name, out var rule))
                    return Fail("INVALID_ARGUMENTS", "工具参数包含未知字段或重复字段。");
                if (!MatchesRule(property.Value, rule))
                    return Fail("INVALID_ARGUMENTS", $"参数 {property.Name} 不符合工具定义。");
            }
        }
        foreach (var field in schema.GetProperty("required").EnumerateArray())
        {
            if (field.GetString() is { } name && !supplied.Contains(name))
                return Fail("INVALID_ARGUMENTS", $"请填写参数 {name}。");
        }
        return null;
    }

    private static bool MatchesRule(JsonElement value, JsonElement rule)
    {
        switch (rule.GetProperty("type").GetString())
        {
            case "integer":
                return value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number)
                    && number >= rule.GetProperty("minimum").GetInt32() && number <= rule.GetProperty("maximum").GetInt32();
            case "boolean":
                return value.ValueKind is JsonValueKind.True or JsonValueKind.False;
            case "string":
                if (value.ValueKind != JsonValueKind.String || value.GetString() is not { } text)
                    return false;
                if (rule.TryGetProperty("minLength", out var min) && text.Trim().Length < min.GetInt32())
                    return false;
                if (rule.TryGetProperty("maxLength", out var max) && text.Length > max.GetInt32())
                    return false;
                if (rule.TryGetProperty("enum", out var options) && !options.EnumerateArray().Any(option => option.GetString() == text))
                    return false;
                return !rule.TryGetProperty("format", out _) || (value.TryGetDateTimeOffset(out _)
                    && (text.EndsWith('Z') || (text.Length > 6 && text[^6] is '+' or '-' && text[^3] == ':')));
            default:
                return false;
        }
    }

    private static string? String(JsonElement args, string name) =>
        args.ValueKind == JsonValueKind.Object && args.TryGetProperty(name, out var value) ? value.GetString()?.Trim() : null;

    private static int Int(JsonElement args, string name, int fallback) =>
        args.ValueKind == JsonValueKind.Object && args.TryGetProperty(name, out var value) ? value.GetInt32() : fallback;

    private static DateTimeOffset? ReadDate(JsonElement args, string name) =>
        args.TryGetProperty(name, out var value) ? value.GetDateTimeOffset().ToUniversalTime() : null;

    private static long? ReadId(JsonElement args, string name) =>
        long.TryParse(String(args, name), NumberStyles.None, CultureInfo.InvariantCulture, out var id) && id > 0 ? id : null;

    private static string? ParseAddress(string? value)
    {
        if (value is null || value.Contains('%'))
            return null;
        var slash = value.IndexOf('/');
        var host = slash < 0 ? value : value[..slash];
        if (!IPAddress.TryParse(host, out var address)
            || (address.AddressFamily == AddressFamily.InterNetwork && !host.Equals(address.ToString(), StringComparison.Ordinal)))
            return null;
        if (slash < 0)
            return IPAddress.Any.Equals(address) || IPAddress.IPv6Any.Equals(address) ? null : address.ToString();

        return IPNetwork.TryParse(value, out var network) && network.PrefixLength > 0 ? network.ToString() : null;
    }
}
