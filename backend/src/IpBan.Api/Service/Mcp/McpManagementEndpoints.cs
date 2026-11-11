using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using IpBan.Api.Models;
using IpBan.Api.Service.impl;
using IpBan.Shared.Models;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Data.Sqlite;

namespace IpBan.Api.Service.Mcp;

internal static class McpManagementEndpoints
{
    internal static void MapMcpManagement(this IEndpointRouteBuilder endpoints)
    {
        var routes = endpoints.MapGroup("/api/admin/v1/mcp");
        routes.MapGet("/settings", (HttpContext context, McpStore store) => RunAsync(context,
            () => store.GetSettingsAsync(context.RequestAborted)));
        routes.MapPut("/settings", (HttpContext context, McpStore store) => RunAsync(context, async () =>
        {
            var request = await ReadAsync(context, McpJsonContext.Default.McpSettingsRequest).ConfigureAwait(false);
            if (request.Enabled is null && request.AuditRetentionDays is null)
                throw new McpAdminProblem(400, "INVALID_MCP_SETTINGS", "请提供要修改的 MCP 设置。");
            return await store.UpdateSettingsAsync(request.Enabled, request.AuditRetentionDays, request.ConfirmShorter,
                Actor(context), RemoteIp(context), context.RequestAborted).ConfigureAwait(false);
        }));
        routes.MapGet("/tools", () => Reply(ApiResult<McpToolView[]>.Ok(McpBusinessTools.Definitions
            .Select(tool => new McpToolView(tool.Name, tool.Group, tool.Title, tool.Description, tool.IsWrite, tool.IsDangerous)).ToArray())));
        routes.MapGet("/keys", (HttpContext context, McpStore store) => RunAsync(context, async () =>
            (await store.ListKeysAsync(context.RequestAborted).ConfigureAwait(false)).Select(KeyView).ToArray()));
        routes.MapPost("/keys", (HttpContext context, McpStore store) => RunAsync(context, async () =>
        {
            var request = await ReadAsync(context, McpJsonContext.Default.McpCreateKeyRequest).ConfigureAwait(false);
            var name = request.Name?.Trim();
            if (string.IsNullOrEmpty(name) || name.Length > 80 || name.Any(char.IsControl)
                || request.Mode is not ("read" or "write") || request.Scopes is not { Length: > 0 }
                || request.Scopes.Length > McpBusinessTools.Definitions.Count
                || (request.ExpiresAtUtc is { } expiration && expiration <= DateTimeOffset.UtcNow))
                throw new McpAdminProblem(400, "INVALID_MCP_KEY", "请检查名称、授权方式、工具权限和有效期。");

            var canWrite = request.Mode == "write";
            var scopes = request.Scopes.Distinct(StringComparer.Ordinal).ToArray();
            if (scopes.Any(scope => !McpBusinessTools.Definitions.Any(tool => tool.Name == scope && (canWrite || !tool.IsWrite))))
                throw new McpAdminProblem(400, "INVALID_MCP_SCOPE", "工具不存在或超出所选授权范围。");

            var created = await store.CreateKeyAsync(name, canWrite, request.ExpiresAtUtc?.ToUniversalTime(), scopes,
                Actor(context), RemoteIp(context), context.RequestAborted).ConfigureAwait(false);
            return new McpCreatedKeyView(KeyView(created.Key), created.Secret);
        }, status: StatusCodes.Status201Created));
        routes.MapPost("/keys/{id:long}/copy", (HttpContext context, McpStore store, long id) => RunAsync(context, async () =>
        {
            var secret = await store.ReadKeySecretAsync(id, Actor(context), RemoteIp(context), context.RequestAborted).ConfigureAwait(false);
            return new McpSecretView(secret ?? throw new McpAdminProblem(404, "MCP_KEY_UNAVAILABLE", "此 API Key 不存在或已失效。"));
        }));
        routes.MapPost("/keys/{id:long}/revoke", (HttpContext context, McpStore store, long id) => RunAsync(context, async () =>
        {
            await store.RevokeKeyAsync(id, Actor(context), RemoteIp(context), context.RequestAborted).ConfigureAwait(false);
            var key = (await store.ListKeysAsync(context.RequestAborted).ConfigureAwait(false)).FirstOrDefault(key => key.Id == id);
            return KeyView(key ?? throw new McpAdminProblem(404, "MCP_KEY_NOT_FOUND", "API Key 不存在。"));
        }));
        routes.MapDelete("/keys/{id:long}", (HttpContext context, McpStore store, long id) => RunAsync(context, async () =>
        {
            if (!await store.DeleteKeyAsync(id, Actor(context), RemoteIp(context), context.RequestAborted).ConfigureAwait(false))
                throw new McpAdminProblem(409, "MCP_KEY_NOT_REVOKED", "请先吊销该 API Key。");
            return true;
        }));
        routes.MapGet("/audits", (HttpContext context, McpStore store) => RunAsync(context, async () =>
        {
            var query = context.Request.Query;
            var from = DateFilter(query, "fromUtc");
            var to = DateFilter(query, "toUtc");
            if (from is not null && to is not null && from > to)
                throw new McpAdminProblem(400, "INVALID_MCP_AUDIT_FILTER", "开始时间不能晚于结束时间。");
            var page = PositiveFilter(query, "page", 1, 1_000_000)!.Value;
            var pageSize = PositiveFilter(query, "pageSize", 20, 100)!.Value;
            var keyId = PositiveFilter(query, "keyId", null, long.MaxValue);
            var tool = FilterText(query, "tool", 100);
            var state = FilterText(query, "status", 16);
            if (state is not (null or "pending" or "success" or "denied" or "error" or "uncertain"))
                throw new McpAdminProblem(400, "INVALID_MCP_AUDIT_FILTER", "调用结果筛选值无效。");
            var result = await store.ListCallsAsync(new McpCallFilter(from, to, keyId, tool, state, (int)page, (int)pageSize),
                context.RequestAborted).ConfigureAwait(false);
            return new McpAuditPageView(result.Items.Select(AuditView).ToArray(), result.Total);
        }));
        routes.MapGet("/audits/{id:long}", (HttpContext context, McpStore store, long id) => RunAsync(context, async () =>
        {
            var detail = await store.GetCallAsync(id, context.RequestAborted).ConfigureAwait(false)
                ?? throw new McpAdminProblem(404, "MCP_AUDIT_NOT_FOUND", "调用记录不存在或已超期清理。");
            return AuditView(detail.Call) with
            {
                Path = detail.Path, RequestHeaders = detail.RequestHeaders, RequestBody = detail.RequestBody,
                ResponseHeaders = detail.ResponseHeaders, ResponseBody = detail.ResponseBody
            };
        }));
    }

    private static async Task<IResult> RunAsync<T>(HttpContext context, Func<Task<T>> action, int status = StatusCodes.Status200OK)
    {
        context.Response.Headers.CacheControl = "no-store";
        try
        {
            if (!HttpMethods.IsGet(context.Request.Method)
                && (context.Request.Headers["X-IPBan-Management"] != "1" || !McpRequestBoundary.IsSameOrigin(context.Request)))
                throw new McpAdminProblem(403, "MCP_MANAGEMENT_ORIGIN_REQUIRED", "请从管理台提交 MCP 设置。");
            return Reply(ApiResult<T>.Ok(await action().ConfigureAwait(false)), status);
        }
        catch (McpAdminProblem problem)
        {
            return Reply(ApiResult<T>.Fail(problem.Code, problem.Message), problem.Status);
        }
        catch (McpStoreException problem)
        {
            return Reply(ApiResult<T>.Fail(problem.Code, problem.Message), problem.HttpStatus);
        }
        catch (JsonException)
        {
            return Reply(ApiResult<T>.Fail("INVALID_JSON", "请求格式无效。"), StatusCodes.Status400BadRequest);
        }
        catch (BadHttpRequestException exception) when (exception.StatusCode == StatusCodes.Status413PayloadTooLarge)
        {
            return Reply(ApiResult<T>.Fail("MCP_MANAGEMENT_BODY_TOO_LARGE", "请求体超过大小限制。"), exception.StatusCode);
        }
        catch (Exception exception) when (exception is SqliteException or IOException or System.Security.Cryptography.CryptographicException)
        {
            return Reply(ApiResult<T>.Fail("MCP_STORAGE_UNAVAILABLE", "MCP 存储或凭据保护暂不可用。"), StatusCodes.Status503ServiceUnavailable);
        }
    }

    private static IResult Reply<T>(ApiResult<T> result, int status = StatusCodes.Status200OK) =>
        Results.Json(result, (JsonTypeInfo<ApiResult<T>>)McpJsonContext.Default.GetTypeInfo(typeof(ApiResult<T>))!, statusCode: status);

    private static async Task<T> ReadAsync<T>(HttpContext context, JsonTypeInfo<T> type) where T : class
    {
        const int limit = 16 * 1024;
        if (context.Request.ContentLength > limit)
            throw new McpAdminProblem(413, "MCP_MANAGEMENT_BODY_TOO_LARGE", "请求体超过大小限制。");
        if (context.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } bodySize)
            bodySize.MaxRequestBodySize = limit;
        return await JsonSerializer.DeserializeAsync(context.Request.Body, type, context.RequestAborted).ConfigureAwait(false)
            ?? throw new McpAdminProblem(400, "INVALID_JSON", "请求内容不能为空。");
    }

    private static string Actor(HttpContext context) => (string)context.Items["ipban.user"]!;
    private static string? RemoteIp(HttpContext context) => context.Connection.RemoteIpAddress?.ToString();

    private static string? FilterText(IQueryCollection query, string key, int limit)
    {
        if (!query.TryGetValue(key, out var value)) return null;
        if (value.Count != 1 || value.ToString().Length > limit)
            throw new McpAdminProblem(400, "INVALID_MCP_AUDIT_FILTER", "筛选值无效。");
        return string.IsNullOrWhiteSpace(value) ? null : value.ToString();
    }

    private static DateTimeOffset? DateFilter(IQueryCollection query, string key)
    {
        if (FilterText(query, key, 40) is not { } value) return null;
        if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var date))
            return date.ToUniversalTime();
        throw new McpAdminProblem(400, "INVALID_MCP_AUDIT_FILTER", "时间筛选值无效。");
    }

    private static long? PositiveFilter(IQueryCollection query, string key, long? fallback, long limit)
    {
        if (FilterText(query, key, 20) is not { } value) return fallback;
        if (long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var number) && number > 0 && number <= limit)
            return number;
        throw new McpAdminProblem(400, "INVALID_MCP_AUDIT_FILTER", "分页或 Key 筛选值无效。");
    }

    private static McpKeyView KeyView(McpApiKey key) => new(key.Id.ToString(CultureInfo.InvariantCulture), key.Name, key.Prefix,
        key.Mode, key.Scopes, key.CreatedAtUtc, key.ExpiresAtUtc, key.RevokedAtUtc);

    private static McpAuditView AuditView(McpCallSummary call) => new(call.Id.ToString(CultureInfo.InvariantCulture), call.OccurredAtUtc,
        call.KeyId?.ToString(CultureInfo.InvariantCulture), call.KeyName, call.KeyPrefix, call.RemoteIp, call.Method, call.Tool,
        call.Status, call.HttpStatus, call.DurationMs, call.TraceId);

    private sealed class McpAdminProblem(int status, string code, string message) : Exception(message)
    {
        public int Status { get; } = status;
        public string Code { get; } = code;
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(McpSettingsRequest))]
[JsonSerializable(typeof(McpCreateKeyRequest))]
[JsonSerializable(typeof(ApiResult<McpSettings>))]
[JsonSerializable(typeof(ApiResult<McpToolView[]>))]
[JsonSerializable(typeof(ApiResult<McpKeyView[]>))]
[JsonSerializable(typeof(ApiResult<McpKeyView>))]
[JsonSerializable(typeof(ApiResult<McpCreatedKeyView>))]
[JsonSerializable(typeof(ApiResult<McpSecretView>))]
[JsonSerializable(typeof(ApiResult<bool>))]
[JsonSerializable(typeof(ApiResult<McpAuditPageView>))]
[JsonSerializable(typeof(ApiResult<McpAuditView>))]
[JsonSerializable(typeof(McpBusinessResult))]
internal sealed partial class McpJsonContext : JsonSerializerContext;
