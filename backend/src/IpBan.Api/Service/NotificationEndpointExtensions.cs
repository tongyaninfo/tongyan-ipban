using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using IpBan.Api.Service.impl;
using IpBan.Api.Workers;
using IpBan.Shared.Logging.Syslog;
using IpBan.Shared.Models;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace IpBan.Api.Service;

public static class NotificationEndpointExtensions
{
    public static IServiceCollection AddIpBanNotifications(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.AddSingleton<NotificationCredentialProtector>();
        services.AddSingleton<NotificationTemplateRenderer>();
        services.TryAddSingleton<INotificationEmailSender, NotificationEmailSender>();
        services.AddSingleton<NotificationService>();
        services.AddHostedService<NotificationWorker>();
        services.ConfigureHttpJsonOptions(options => options.SerializerOptions.TypeInfoResolverChain.Insert(0, NotificationJsonContext.Default));
        return services;
    }

    public static IEndpointRouteBuilder MapNotificationEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/admin/v1/notifications");
        group.MapGet("/settings", (HttpContext context, NotificationService service) => RunAsync(context,
            () => service.GetSettingsAsync(context.RequestAborted), NotificationJsonContext.Default.ApiResultNotificationSettings));
        group.MapPut("/settings", (HttpContext context, NotificationService service) => RunAsync(context, async () =>
        {
            var request = await ReadAsync(context, NotificationJsonContext.Default.UpdateNotificationSettingsRequest).ConfigureAwait(false);
            return await service.SaveSettingsAsync(request, Actor(context), context.Connection.RemoteIpAddress?.ToString(), context.RequestAborted).ConfigureAwait(false);
        }, NotificationJsonContext.Default.ApiResultNotificationSettings));
        group.MapPost("/test", (HttpContext context, NotificationService service) => RunAsync(context, async () =>
        {
            var request = await ReadAsync(context, NotificationJsonContext.Default.TestNotificationRequest).ConfigureAwait(false);
            return await service.QueueTestAsync(request.Recipient, Actor(context), context.Connection.RemoteIpAddress?.ToString(), context.RequestAborted).ConfigureAwait(false);
        }, NotificationJsonContext.Default.ApiResultNotificationTestResult));
        group.MapGet("/messages", (HttpContext context, NotificationService service, string? page, string? pageSize, string? status, string? eventType) => RunAsync(context,
            () => service.ListMessagesAsync(ReadPage(page, 1), ReadPage(pageSize, 20), status, eventType, context.RequestAborted), NotificationJsonContext.Default.ApiResultNotificationMessagePage));
        group.MapGet("/messages/{id}", (HttpContext context, NotificationService service, string id) => RunAsync(context,
            () => service.GetMessageAsync(id, context.RequestAborted), NotificationJsonContext.Default.ApiResultNotificationMessageDetail));
        group.MapGet("/preview/{eventType}", (HttpContext context, NotificationService service, string eventType) => RunAsync(context,
            () => Task.FromResult(service.Preview(eventType)), NotificationJsonContext.Default.ApiResultNotificationRenderedEmail));
        return endpoints;
    }

    private static string Actor(HttpContext context) => context.Items["ipban.user"] as string ?? "local-admin";
    private static int ReadPage(string? value, int fallback) => value is null ? fallback : int.TryParse(value, out var parsed) ? parsed
        : throw new NotificationRequestException(400, "INVALID_NOTIFICATION_FILTER", "邮件列表分页参数无效。");

    private static async Task<IResult> RunAsync<T>(HttpContext context, Func<Task<T>> action, JsonTypeInfo<ApiResult<T>> type)
    {
        context.Response.Headers.CacheControl = "no-store";
        try
        {
            if (!HttpMethods.IsGet(context.Request.Method) && (context.Request.Headers["X-IPBan-Management"] != "1" || !SameOrigin(context.Request)))
                throw new NotificationRequestException(403, "NOTIFICATION_ORIGIN_REQUIRED", "请从管理台提交通知设置或测试请求。");
            return Results.Json(ApiResult<T>.Ok(await action().ConfigureAwait(false)), type);
        }
        catch (NotificationRequestException exception)
        {
            if (exception.Status == 429) context.Response.Headers.RetryAfter = "60";
            return Results.Json(ApiResult<T>.Fail(exception.Code, exception.Message), type, statusCode: exception.Status);
        }
        catch (JsonException)
        { return Results.Json(ApiResult<T>.Fail("INVALID_JSON", "请求 JSON 格式无效。"), type, statusCode: 400); }
        catch (BadHttpRequestException exception) when (exception.StatusCode == 413)
        { return Results.Json(ApiResult<T>.Fail("NOTIFICATION_BODY_TOO_LARGE", "请求体超过大小限制。"), type, statusCode: 413); }
        catch (Exception exception) when (exception is SqliteException or IOException or UnauthorizedAccessException or CryptographicException)
        {
            context.RequestServices.GetService<SyslogRuntime>()?.Publish("ipban-mail", "mail.storage.unavailable", SyslogSeverity.Error,
                "邮件通知的配置、凭据或审计暂不可用。", result: "NOTIFICATION_STORAGE_UNAVAILABLE", traceId: context.TraceIdentifier);
            return Results.Json(ApiResult<T>.Fail("NOTIFICATION_STORAGE_UNAVAILABLE", "通知配置、凭据或审计暂不可用，请检查服务状态。"), type, statusCode: 503);
        }
    }

    private static async Task<T> ReadAsync<T>(HttpContext context, JsonTypeInfo<T> type) where T : class
    {
        const int limit = 32 * 1024;
        if (context.Request.ContentLength > limit) throw new NotificationRequestException(413, "NOTIFICATION_BODY_TOO_LARGE", "请求体超过大小限制。");
        if (context.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } feature) feature.MaxRequestBodySize = limit;
        return await JsonSerializer.DeserializeAsync(context.Request.Body, type, context.RequestAborted).ConfigureAwait(false)
            ?? throw new NotificationRequestException(400, "INVALID_JSON", "请求内容不能为空。");
    }

    private static bool SameOrigin(HttpRequest request)
    {
        if (request.Headers["Sec-Fetch-Site"] is var site && site.Count > 0 && site.ToString() is not ("same-origin" or "none")) return false;
        if (!request.Headers.TryGetValue("Origin", out var origin)) return true;
        return origin.Count == 1 && Uri.TryCreate(origin[0], UriKind.Absolute, out var uri)
            && string.Equals(uri.GetLeftPart(UriPartial.Authority), $"{request.Scheme}://{request.Host}", StringComparison.OrdinalIgnoreCase);
    }
}
