using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using IpBan.Api.Models;
using IpBan.Api.Service.impl;
using IpBan.Api.Service.Mcp;
using IpBan.Shared.Logging.Syslog;
using IpBan.Shared.Models;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Data.Sqlite;

namespace IpBan.Api.Service;

public static class SyslogEndpointExtensions
{
    public static IEndpointRouteBuilder MapSyslogEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/admin/v1/syslog");
        group.MapGet("/settings", (HttpContext context, SyslogManagementService service) => RunAsync(context,
            () => service.GetAsync(context.RequestAborted), SyslogApiJsonContext.Default.ApiResultSyslogSettings));
        group.MapPut("/settings", (HttpContext context, SyslogManagementService service) => RunAsync(context, async () =>
        {
            var body = await ReadAsync(context, SyslogJsonContext.Default.SyslogSettings).ConfigureAwait(false);
            return await service.SaveAsync(body, Actor(context), RemoteIp(context), context.RequestAborted).ConfigureAwait(false);
        }, SyslogApiJsonContext.Default.ApiResultSyslogSettings));
        group.MapGet("/status", (HttpContext context, SyslogManagementService service) => RunAsync(context,
            () => service.GetStatusAsync(context.RequestAborted), SyslogApiJsonContext.Default.ApiResultSyslogStatusResult));
        group.MapPost("/test", (HttpContext context, SyslogManagementService service) => RunAsync(context, async () =>
        {
            var body = await ReadAsync(context, SyslogApiJsonContext.Default.SyslogTestRequest).ConfigureAwait(false);
            return await service.TestAsync(body, Actor(context), RemoteIp(context), context.RequestAborted).ConfigureAwait(false);
        }, SyslogApiJsonContext.Default.ApiResultSyslogTestResult));
        return endpoints;
    }

    private static async Task<IResult> RunAsync<T>(HttpContext context, Func<Task<T>> execute, JsonTypeInfo<ApiResult<T>> type)
    {
        context.Response.Headers.CacheControl = "no-store";
        try
        {
            if (context.Items["ipban.user"] is not string { Length: > 0 })
                throw new SyslogRequestException(401, "AUTH_REQUIRED", "请先登录管理台。");
            if (!HttpMethods.IsGet(context.Request.Method) && !IsManagementWrite(context.Request))
                throw new SyslogRequestException(403, "SYSLOG_ORIGIN_REQUIRED", "请从同源管理台提交 Syslog 请求。");
            return Results.Json(ApiResult<T>.Ok(await execute().ConfigureAwait(false)), type);
        }
        catch (SyslogRequestException error)
        {
            if (error.Status == 429) context.Response.Headers.RetryAfter = "5";
            return Results.Json(ApiResult<T>.Fail(error.Code, error.Message), type, statusCode: error.Status);
        }
        catch (JsonException)
        {
            return Results.Json(ApiResult<T>.Fail("INVALID_JSON", "请求 JSON 格式无效。"), type, statusCode: 400);
        }
        catch (BadHttpRequestException error) when (error.StatusCode == 413)
        {
            return Results.Json(ApiResult<T>.Fail("SYSLOG_BODY_TOO_LARGE", "请求体超过大小限制。"), type, statusCode: 413);
        }
        catch (Exception error) when (error is SqliteException or IOException or UnauthorizedAccessException)
        {
            return Results.Json(ApiResult<T>.Fail("SYSLOG_STORAGE_UNAVAILABLE", "Syslog 配置或审计暂不可用。"), type, statusCode: 503);
        }
    }

    private static bool IsManagementWrite(HttpRequest request) => request.Headers["X-IPBan-Management"] == "1"
        && (request.Headers["Sec-Fetch-Site"] is var site && (site.Count == 0 || site.ToString() is "same-origin" or "none"))
        && McpRequestBoundary.IsSameOrigin(request);

    private static async Task<T> ReadAsync<T>(HttpContext context, JsonTypeInfo<T> type) where T : class
    {
        const int limit = 16 * 1024;
        if (context.Request.ContentLength > limit)
            throw new SyslogRequestException(413, "SYSLOG_BODY_TOO_LARGE", "请求体超过大小限制。");
        if (context.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } size)
            size.MaxRequestBodySize = limit;
        return await JsonSerializer.DeserializeAsync(context.Request.Body, type, context.RequestAborted).ConfigureAwait(false)
            ?? throw new SyslogRequestException(400, "INVALID_JSON", "请求内容不能为空。");
    }

    private static string Actor(HttpContext context) => (string)context.Items["ipban.user"]!;
    private static string? RemoteIp(HttpContext context) => context.Connection.RemoteIpAddress?.ToString();
}
