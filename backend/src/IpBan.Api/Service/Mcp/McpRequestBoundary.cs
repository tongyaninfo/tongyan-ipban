using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
using IpBan.Api.Models;
using IpBan.Api.Service.impl;
using IpBan.Shared.Logging.Syslog;
using Microsoft.AspNetCore.Http.Features;

namespace IpBan.Api.Service.Mcp;

/// <summary>在协议处理器前验证传输和凭据，并持久记录请求及实际协议响应。</summary>
internal sealed partial class McpRequestBoundary(McpStore store, McpAdmission admission, ILogger<McpRequestBoundary> logger) : IMiddleware
{
    private const int RequestLimit = 64 * 1024;
    private const int ResponseLimit = 1024 * 1024;

    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var request = context.Request;
        if (!request.Path.StartsWithSegments(McpEndpointExtensions.Path, out var remaining)
            || (remaining.HasValue && remaining != "/"))
        {
            await next(context).ConfigureAwait(false);
            return;
        }

        using var rate = admission.ByIp.AttemptAcquire(context.Connection.RemoteIpAddress?.ToString() ?? "unknown");
        using var parallel = admission.Concurrent.AttemptAcquire();
        (int Status, string Message) rejection = !IsSameOrigin(request) ? (StatusCodes.Status403Forbidden, "请求来源不受信任。")
            : !rate.IsAcquired || !parallel.IsAcquired ? (StatusCodes.Status429TooManyRequests, "请求过多，请稍后重试。")
            : (0, string.Empty);
        var started = Stopwatch.GetTimestamp();
        var originalBody = request.Body;
        var originalOutput = context.Response.Body;
        using var output = new LimitedOutput(ResponseLimit);
        context.Response.Body = output;
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers["X-Request-ID"] = context.TraceIdentifier;
        long? auditId = null;
        McpRequestContext? call = null;

        try
        {
            string? secret = null;
            McpApiKey? key = null;
            JsonDocument? document = null;
            using var body = new MemoryStream();
            try
            {
                if (rejection.Status == 0)
                {
                    secret = ReadBearer(request);
                    if (!(await store.GetSettingsAsync(context.RequestAborted).ConfigureAwait(false)).Enabled)
                        rejection = (StatusCodes.Status503ServiceUnavailable, "MCP 服务已停止。");
                    else if (secret is null || (key = await store.AuthenticateAsync(secret, context.RequestAborted).ConfigureAwait(false)) is null)
                        rejection = (StatusCodes.Status401Unauthorized, "API Key 无效、已过期或已吊销。");
                    else if (HttpMethods.IsPost(request.Method))
                    {
                        if (!await ReadBodyAsync(request, body, context.RequestAborted).ConfigureAwait(false))
                            rejection = (StatusCodes.Status413PayloadTooLarge, "请求体超过 64 KiB。");
                        else
                        {
                            try
                            {
                                body.Position = 0;
                                document = await JsonDocument.ParseAsync(body, new JsonDocumentOptions { AllowDuplicateProperties = false },
                                    context.RequestAborted).ConfigureAwait(false);
                                if (document.RootElement.ValueKind != JsonValueKind.Object)
                                    rejection = (StatusCodes.Status400BadRequest, "请求必须是单个 JSON-RPC 消息。");
                            }
                            catch (JsonException)
                            {
                                rejection = (StatusCodes.Status400BadRequest, "请求 JSON 无效。");
                            }
                        }
                    }
                }

                var method = document is null ? request.Method : ReadString(document.RootElement, "method", 80, secret) ?? request.Method;
                var tool = document?.RootElement is { ValueKind: JsonValueKind.Object } root
                    && root.TryGetProperty("params", out var parameters) ? ReadString(parameters, "name", 100, secret) : null;
                auditId = await store.BeginCallAsync(new McpCallStart(key, context.TraceIdentifier,
                    context.Connection.RemoteIpAddress?.ToString(), method, tool,
                    key is null ? null : McpAuditPayload.Headers(request.Headers, secret),
                    rejection.Status == 0 && document is not null ? McpAuditPayload.Json(document.RootElement, secret) : null),
                    context.RequestAborted).ConfigureAwait(false);

                if (rejection.Status != 0)
                {
                    if (rejection.Status == StatusCodes.Status401Unauthorized) context.Response.Headers.WWWAuthenticate = "Bearer";
                    await WriteErrorAsync(context, rejection.Status, rejection.Message).ConfigureAwait(false);
                }
                else
                {
                    call = new McpRequestContext(key!);
                    context.Features.Set(call);
                    if (document is not null)
                    {
                        body.Position = 0;
                        request.Body = body;
                    }
                    await next(context).ConfigureAwait(false);
                }
            }
            finally
            {
                document?.Dispose();
                request.Body = originalBody;
                context.Features.Set<McpRequestContext>(null);
            }

            await context.Response.BodyWriter.FlushAsync(CancellationToken.None).ConfigureAwait(false);
            var payload = Encoding.UTF8.GetString(output.GetBuffer(), 0, (int)output.Length);
            var status = rejection.Status != 0 ? "denied" : call?.Status ?? ResultStatus(context.Response.StatusCode, payload);
            if (context.Response.StatusCode != StatusCodes.Status204NoContent)
                context.Response.ContentLength = output.Length;
            await CompleteAsync(auditId.Value, status, context, started, secret, payload, call).ConfigureAwait(false);
            context.Response.Body = originalOutput;
            output.Position = 0;
            await output.CopyToAsync(originalOutput, context.RequestAborted).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            if (auditId is { } id && ReferenceEquals(context.Response.Body, output))
            {
                try
                {
                    await CompleteAsync(id, call?.WriteStarted == true ? "uncertain" : "error", context, started, null, null, call,
                        StatusCodes.Status503ServiceUnavailable).ConfigureAwait(false);
                }
                catch (Exception auditError) when (auditError is not OutOfMemoryException)
                {
                    LogAuditFailure(logger, id);
                }
            }

            context.Response.Body = originalOutput;
            if (!context.Response.HasStarted && !context.RequestAborted.IsCancellationRequested)
            {
                context.Response.Clear();
                context.Response.Headers.CacheControl = "no-store";
                context.Response.Headers["X-Request-ID"] = context.TraceIdentifier;
                await WriteErrorAsync(context, StatusCodes.Status503ServiceUnavailable,
                    call?.WriteStarted == true ? "执行结果待核验，请按关联 ID 查询记录。" : "MCP 请求暂时无法完成。").ConfigureAwait(false);
            }
        }
        finally
        {
            context.Response.Body = originalOutput;
        }
    }

    internal static bool IsSameOrigin(HttpRequest request)
    {
        if (!request.Headers.TryGetValue("Origin", out var origin)) return true;
        return origin.Count == 1 && Uri.TryCreate(origin[0], UriKind.Absolute, out var supplied)
            && Uri.TryCreate($"{request.Scheme}://{request.Host}", UriKind.Absolute, out var expected)
            && supplied.Scheme == expected.Scheme && supplied.IdnHost == expected.IdnHost && supplied.Port == expected.Port
            && string.IsNullOrEmpty(supplied.UserInfo) && supplied.PathAndQuery == "/" && string.IsNullOrEmpty(supplied.Fragment);
    }

    private static string? ReadBearer(HttpRequest request)
    {
        if (request.Headers.Authorization.Count != 1 || request.Headers.Authorization[0] is not { } value
            || value.Length > 256 || !value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return null;
        var secret = value[7..];
        return secret.Length > 0 && !secret.Any(char.IsWhiteSpace) ? secret : null;
    }

    private static async Task<bool> ReadBodyAsync(HttpRequest request, MemoryStream buffer, CancellationToken cancellationToken)
    {
        if (request.ContentLength > RequestLimit) return false;
        if (request.HttpContext.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } size)
            size.MaxRequestBodySize = RequestLimit + 1;
        var bytes = new byte[8192];
        while (buffer.Length <= RequestLimit)
        {
            int count;
            try
            {
                count = await request.Body.ReadAsync(bytes.AsMemory(0, Math.Min(bytes.Length, RequestLimit + 1 - (int)buffer.Length)), cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (BadHttpRequestException exception) when (exception.StatusCode == StatusCodes.Status413PayloadTooLarge)
            {
                return false;
            }
            if (count == 0) return true;
            buffer.Write(bytes, 0, count);
        }
        return false;
    }

    private async Task CompleteAsync(long id, string status, HttpContext context, long started, string? secret, string? payload,
        McpRequestContext? call, int? httpStatus = null)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await store.CompleteCallAsync(id, status, httpStatus ?? context.Response.StatusCode,
            (long)Stopwatch.GetElapsedTime(started).TotalMilliseconds, McpAuditPayload.Headers(context.Response.Headers, secret),
            payload is null ? null : McpAuditPayload.Response(payload, secret), deadline.Token).ConfigureAwait(false);
        var (severity, message) = status switch
        {
            "denied" => (SyslogSeverity.Warning, "MCP 请求已被拒绝。"),
            "error" => (SyslogSeverity.Error, "MCP 调用执行失败。"),
            "uncertain" => (SyslogSeverity.Error, "MCP 调用结果待核验。"),
            _ when call?.WriteStarted == true => (SyslogSeverity.Notice, "MCP 写操作已完成。"),
            _ => (SyslogSeverity.Informational, "MCP 读取请求已完成。")
        };
        context.RequestServices.GetService<SyslogRuntime>()?.Publish("ipban-mcp", "mcp.call.complete", severity, message,
            result: status, sourceId: id.ToString(CultureInfo.InvariantCulture), traceId: context.TraceIdentifier,
            remoteIp: context.Connection.RemoteIpAddress?.ToString(), actor: call?.Key.Id.ToString(CultureInfo.InvariantCulture));
    }

    private static string? ReadString(JsonElement element, string property, int limit, string? secret) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value)
        && value.ValueKind == JsonValueKind.String && value.GetString() is { } text && text.Length <= limit
            ? McpAuditPayload.Value(text, secret) : null;

    private static string ResultStatus(int httpStatus, string payload) => httpStatus >= 500 ? "error"
        : httpStatus >= 400 ? "denied" : McpAuditPayload.HasProtocolError(payload) ? "error" : "success";

    private static async Task WriteErrorAsync(HttpContext context, int status, string message)
    {
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/json; charset=utf-8";
        using var writer = new Utf8JsonWriter(context.Response.BodyWriter);
        writer.WriteStartObject();
        writer.WriteString("jsonrpc", "2.0");
        writer.WriteNull("id");
        writer.WriteStartObject("error");
        writer.WriteNumber("code", -32000);
        writer.WriteString("message", message);
        writer.WriteEndObject();
        writer.WriteEndObject();
        writer.Flush();
        await context.Response.BodyWriter.FlushAsync(context.RequestAborted).ConfigureAwait(false);
    }

    [LoggerMessage(1, LogLevel.Error, "MCP 调用审计 {AuditId} 的结果未能保存。")]
    private static partial void LogAuditFailure(ILogger logger, long auditId);

    private sealed class LimitedOutput(int limit) : MemoryStream
    {
        private void Check(int length)
        {
            if (Position + length > limit) throw new IOException("MCP response exceeds its configured size limit.");
        }

        public override void Write(byte[] buffer, int offset, int count) { Check(count); base.Write(buffer, offset, count); }
        public override void Write(ReadOnlySpan<byte> buffer) { Check(buffer.Length); base.Write(buffer); }
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        { Check(count); return base.WriteAsync(buffer, offset, count, cancellationToken); }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        { Check(buffer.Length); return base.WriteAsync(buffer, cancellationToken); }
    }
}

internal sealed class McpAdmission : IDisposable
{
    internal PartitionedRateLimiter<string> ByIp { get; } = PartitionedRateLimiter.Create<string, string>(ip =>
        RateLimitPartition.GetFixedWindowLimiter(ip, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 120, Window = TimeSpan.FromMinutes(1), AutoReplenishment = true, QueueLimit = 0
        }));

    internal ConcurrencyLimiter Concurrent { get; } = new(new ConcurrencyLimiterOptions { PermitLimit = 16, QueueLimit = 0 });

    public void Dispose()
    {
        ByIp.Dispose();
        Concurrent.Dispose();
    }
}
