using System.Globalization;
using IpBan.Shared.Logging.Syslog;
using Microsoft.AspNetCore.Routing;

namespace IpBan.Api.Service;

public static class ApiRequestLogging
{
    public static async Task InvokeAsync(HttpContext context, RequestDelegate next, SyslogRuntime syslog)
    {
        if (!context.Request.Path.StartsWithSegments("/api") && !context.Request.Path.StartsWithSegments(ManagementHub.Path))
        {
            await next(context).ConfigureAwait(false);
            return;
        }

        var status = StatusCodes.Status500InternalServerError;
        try
        {
            await next(context).ConfigureAwait(false);
            status = context.Response.StatusCode;
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            status = 499;
            throw;
        }
        finally
        {
            var severity = status switch
            {
                >= 500 => SyslogSeverity.Error,
                401 or 403 or 429 => SyslogSeverity.Warning,
                499 => SyslogSeverity.Debug,
                _ => SyslogSeverity.Informational
            };
            var route = (context.GetEndpoint() as RouteEndpoint)?.RoutePattern.RawText ?? "未匹配路由";
            var statusText = status.ToString(CultureInfo.InvariantCulture);
            // 使用服务端路由模板，省略包含用户输入和可能凭据的原始请求路径、查询和正文。
            syslog.Publish("ipban-http", "http.request.complete", severity,
                $"管理接口请求结束，路由 {route}，状态码 {statusText}。", result: statusText,
                remoteIp: context.Connection.RemoteIpAddress?.ToString(), actor: context.Items["ipban.user"] as string,
                traceId: context.TraceIdentifier);
        }
    }
}
