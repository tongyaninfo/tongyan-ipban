using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using IpBan.Api.Models;
using IpBan.Api.Service.impl;
using IpBan.Shared.Logging.Syslog;
using IpBan.Shared.Models;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Data.Sqlite;

namespace IpBan.Api.Service;

public static class IpLocationEndpointExtensions
{
    public static IEndpointRouteBuilder MapIpLocationEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var routes = endpoints.MapGroup("/api/admin/v1/ip-location");
        routes.MapGet("/settings", (HttpContext context, IpLocationService service) => RunAsync(context,
            () => service.GetSettingsAsync(context.RequestAborted), IpLocationJsonContext.Default.ApiResultIpLocationSettings));
        routes.MapPut("/settings", (HttpContext context, IpLocationService service) => RunAsync(context, async () =>
        {
            var settings = await ReadAsync(context, IpLocationJsonContext.Default.IpLocationSettings).ConfigureAwait(false);
            if (!IpLocationService.TryValidate(settings, out var normalized, out var message))
                throw new RequestProblem(400, "INVALID_IP_LOCATION_SETTINGS", message);
            return await service.UpdateSettingsAsync(normalized, context.Items["ipban.user"] as string ?? "local-admin",
                context.Connection.RemoteIpAddress?.ToString(), context.RequestAborted).ConfigureAwait(false);
        }, IpLocationJsonContext.Default.ApiResultIpLocationSettings));
        routes.MapPost("/lookup", (HttpContext context, IpLocationService service) => RunAsync(context, async () =>
        {
            var request = await ReadAsync(context, IpLocationJsonContext.Default.IpLocationLookupRequest).ConfigureAwait(false);
            if (request.Ips is null || request.Ips.Length > 100 || request.Ips.Any(ip => ip is null || ip.Length > 128))
                throw new RequestProblem(400, "INVALID_IP_LOCATION_LOOKUP", "每批最多查询 100 个 IP，每项长度不得超过 128 个字符。");
            return service.Lookup(request.Ips);
        }, IpLocationJsonContext.Default.ApiResultIpLocationBatchResult));
        return endpoints;
    }

    private static async Task<IResult> RunAsync<T>(HttpContext context, Func<Task<T>> action, JsonTypeInfo<ApiResult<T>> type)
    {
        context.Response.Headers.CacheControl = "no-store";
        try
        {
            if (!HttpMethods.IsGet(context.Request.Method) && (context.Request.Headers["X-IPBan-Management"] != "1" || !SameOrigin(context.Request)))
                throw new RequestProblem(403, "IP_LOCATION_ORIGIN_REQUIRED", "请从管理台提交 IP 解析请求。");
            return Results.Json(ApiResult<T>.Ok(await action().ConfigureAwait(false)), type);
        }
        catch (RequestProblem problem)
        { return Results.Json(ApiResult<T>.Fail(problem.Code, problem.Message), type, statusCode: problem.Status); }
        catch (JsonException)
        { return Results.Json(ApiResult<T>.Fail("INVALID_JSON", "请求 JSON 格式无效。"), type, statusCode: 400); }
        catch (BadHttpRequestException exception) when (exception.StatusCode == 413)
        { return Results.Json(ApiResult<T>.Fail("IP_LOCATION_BODY_TOO_LARGE", "请求体超过大小限制。"), type, statusCode: 413); }
        catch (Exception exception) when (exception is SqliteException or IOException or UnauthorizedAccessException)
        {
            context.RequestServices.GetService<SyslogRuntime>()?.Publish("ipban-geoip", "geoip.storage.unavailable", SyslogSeverity.Error,
                "IP 归属地配置或审计暂不可用。", result: "IP_LOCATION_STORAGE_UNAVAILABLE", traceId: context.TraceIdentifier);
            return Results.Json(ApiResult<T>.Fail("IP_LOCATION_STORAGE_UNAVAILABLE", "IP 解析配置或审计暂不可用，请稍后重试。"), type, statusCode: 503);
        }
    }

    private static async Task<T> ReadAsync<T>(HttpContext context, JsonTypeInfo<T> type) where T : class
    {
        const int limit = 16 * 1024;
        if (context.Request.ContentLength > limit) throw new RequestProblem(413, "IP_LOCATION_BODY_TOO_LARGE", "请求体超过大小限制。");
        if (context.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } feature) feature.MaxRequestBodySize = limit;
        return await JsonSerializer.DeserializeAsync(context.Request.Body, type, context.RequestAborted).ConfigureAwait(false)
            ?? throw new RequestProblem(400, "INVALID_JSON", "请求内容不能为空。");
    }

    private static bool SameOrigin(HttpRequest request)
    {
        if (request.Headers["Sec-Fetch-Site"] is var site && site.Count > 0 && site.ToString() is not ("same-origin" or "none")) return false;
        if (!request.Headers.TryGetValue("Origin", out var origin)) return true;
        return origin.Count == 1 && Uri.TryCreate(origin[0], UriKind.Absolute, out var uri)
            && string.Equals(uri.GetLeftPart(UriPartial.Authority), $"{request.Scheme}://{request.Host}", StringComparison.OrdinalIgnoreCase);
    }

    private sealed class RequestProblem(int status, string code, string message) : Exception(message)
    {
        public int Status { get; } = status;
        public string Code { get; } = code;
    }
}
