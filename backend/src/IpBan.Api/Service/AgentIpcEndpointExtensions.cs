using System.Text.Json;
using System.Globalization;
using IpBan.Api.Service.impl;
using Microsoft.Data.Sqlite;
using IpBan.Shared.Models;
using IpBan.Shared.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace IpBan.Api.Service;

/// <summary>
/// 管理台当前连接和人工封禁接口。Program.cs 只需在构建后调用 MapIpBanAgentIpcEndpoints。
/// </summary>
public static class AgentIpcEndpointExtensions
{
    public static IEndpointRouteBuilder MapIpBanAgentIpcEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(
            "/api/admin/v1/connections",
            async (IAgentIpcClient client, CancellationToken cancellationToken) =>
            {
                var result = await client.ListConnectionsAsync(cancellationToken).ConfigureAwait(false);
                if (!result.Success || result.Data is null)
                {
                    return Results.Ok(result);
                }

                // 管理台隐藏自身的管理 API 连接，避免把页面轮询连接误显示为业务会话。
                var visibleConnections = result.Data
                    .Where(connection => !IsIpBanManagementConnection(connection))
                    .ToArray();
                return Results.Ok(result with { Data = visibleConnections });
            });

        endpoints.MapGet(
            "/api/admin/v1/login-events",
            async (int? limit, IAgentIpcClient client, CancellationToken cancellationToken) =>
            {
                var result = await client.ListLoginEventsAsync(
                    limit ?? 100,
                    cancellationToken).ConfigureAwait(false);
                return Results.Ok(result);
            });

        endpoints.MapPost(
            "/api/admin/v1/bans",
            async (HttpContext context, IAgentIpcClient client, SqliteAdminStore store, CancellationToken cancellationToken) =>
            {
                ManualBanHttpRequest? body;
                try
                {
                    body = await JsonSerializer.DeserializeAsync(
                        context.Request.Body,
                        IpBanApiJsonContext.Default.ManualBanHttpRequest,
                        cancellationToken).ConfigureAwait(false);
                }
                catch (JsonException)
                {
                    return Results.BadRequest(ApiResult<ManualBanResult>.Fail(
                        "INVALID_REQUEST",
                        "请求 JSON 无效。"));
                }

                if (body is null || string.IsNullOrWhiteSpace(body.SourceAddress))
                {
                    return Results.BadRequest(ApiResult<ManualBanResult>.Fail(
                        "INVALID_SOURCE_ADDRESS",
                        "sourceAddress 不能为空。"));
                }

                if (!ManualBanDuration.IsValid(body.DurationSeconds))
                    return Results.BadRequest(ApiResult<ManualBanResult>.Fail("INVALID_DURATION",
                        "封禁时长须为 1 至 604800 秒，或使用 -1 表示永久封禁。"));

                body = body with { SourceAddress = body.SourceAddress.Trim(), Reason = body.Reason?.Trim() };
                if (body.Reason is { Length: > 500 }
                    || (body.DurationSeconds == ManualBanDuration.Permanent && string.IsNullOrEmpty(body.Reason)))
                    return Results.BadRequest(ApiResult<ManualBanResult>.Fail("INVALID_BAN_REASON",
                        "永久封禁必须填写原因，封禁原因最多 500 字。"));

                var actor = context.Items["ipban.user"] as string;
                var remoteIp = context.Connection.RemoteIpAddress?.ToString();
                try
                {
                    // 意图审计成功后才下发防火墙操作。执行结果单独落审计，避免将请求当作已生效。
                    await store.AppendAuditAsync("ban.create.request", "firewall", body.SourceAddress,
                        JsonSerializer.Serialize(body, IpBanApiJsonContext.Default.ManualBanHttpRequest), remoteIp, true,
                        actor, context.TraceIdentifier, result: "requested", cancellationToken: cancellationToken).ConfigureAwait(false);
                    var result = await client.BanAsync(body.SourceAddress, body.DurationSeconds, body.DisconnectExisting,
                        context.TraceIdentifier, cancellationToken).ConfigureAwait(false);
                    await store.AppendAuditAsync("ban.create", "firewall", body.SourceAddress,
                        JsonSerializer.Serialize(result, IpBanJsonContext.Default.ApiResultManualBanResult), remoteIp,
                        result.Success, actor, context.TraceIdentifier, result: result.Code, publish: result.Data is null,
                        cancellationToken: CancellationToken.None).ConfigureAwait(false);
                    return Results.Ok(result);
                }
                catch (Exception exception) when (exception is SqliteException or IOException)
                {
                    store.PublishAudit("ban.create", null, actor, remoteIp, false, context.TraceIdentifier, "BAN_AUDIT_FAILED");
                    return Results.Json(ApiResult<ManualBanResult>.Fail("BAN_AUDIT_FAILED",
                        "审计或执行记录写入失败，请刷新核对实际状态。"),
                        IpBanJsonContext.Default.ApiResultManualBanResult, statusCode: StatusCodes.Status500InternalServerError);
                }
            });

        endpoints.MapPost("/api/admin/v1/bans/unban", async (HttpContext context, IAgentIpcClient client,
            SqliteAdminStore store, CancellationToken cancellationToken) =>
        {
            ManualUnbanHttpRequest? body;
            try
            {
                body = await JsonSerializer.DeserializeAsync(context.Request.Body,
                    IpBanApiJsonContext.Default.ManualUnbanHttpRequest, cancellationToken).ConfigureAwait(false);
            }
            catch (JsonException)
            {
                return Results.BadRequest(ApiResult<FirewallActionResult>.Fail("INVALID_REQUEST", "请求 JSON 无效。"));
            }
            if (body is null || string.IsNullOrWhiteSpace(body.SourceAddress)
                || !long.TryParse(body.ActionId, NumberStyles.None, CultureInfo.InvariantCulture, out var actionId) || actionId <= 0)
                return Results.BadRequest(ApiResult<FirewallActionResult>.Fail("INVALID_BAN_ACTION", "请选择有效的封禁记录。"));

            var actor = context.Items["ipban.user"] as string;
            var remoteIp = context.Connection.RemoteIpAddress?.ToString();
            try
            {
                // 先可靠记录管理员意图，审计不可用时不下发防火墙操作。
                await store.AppendAuditAsync("ban.unban.request", "firewall", body.ActionId, null, remoteIp, true,
                    actor, context.TraceIdentifier, result: "requested", cancellationToken: cancellationToken).ConfigureAwait(false);
                var result = await client.UnbanAsync(body.SourceAddress, actionId, context.TraceIdentifier, cancellationToken).ConfigureAwait(false);
                // 收到执行结果后即使浏览器断开，也尽量完成结果审计。
                await store.AppendAuditAsync("ban.unban", "firewall", body.ActionId,
                    JsonSerializer.Serialize(result, IpBanJsonContext.Default.ApiResultFirewallActionResult), remoteIp, result.Success,
                    actor, context.TraceIdentifier, result: result.Code, publish: result.Data is null,
                    cancellationToken: CancellationToken.None).ConfigureAwait(false);
                var status = result.Success ? StatusCodes.Status200OK : result.Code switch
                {
                    "INVALID_BAN_ACTION" => StatusCodes.Status400BadRequest,
                    "BAN_NOT_FOUND" => StatusCodes.Status404NotFound,
                    "BAN_NOT_CURRENT" => StatusCodes.Status409Conflict,
                    _ => StatusCodes.Status502BadGateway
                };
                return Results.Json(result, IpBanJsonContext.Default.ApiResultFirewallActionResult, statusCode: status);
            }
            catch (Exception exception) when (exception is SqliteException or IOException)
            {
                store.PublishAudit("ban.unban", null, actor, remoteIp, false, context.TraceIdentifier, "UNBAN_AUDIT_FAILED");
                return Results.Json(ApiResult<FirewallActionResult>.Fail("UNBAN_AUDIT_FAILED", "审计或执行记录写入失败，请刷新核对实际状态。"),
                    IpBanJsonContext.Default.ApiResultFirewallActionResult,
                    statusCode: StatusCodes.Status500InternalServerError);
            }
        });

        endpoints.MapPost(
            "/api/admin/v1/connections/disconnect",
            async (HttpRequest request, IAgentIpcClient client, SqliteAdminStore store, CancellationToken cancellationToken) =>
            {
                ConnectionSnapshotContract? body;
                try
                {
                    body = await JsonSerializer.DeserializeAsync(
                        request.Body,
                        IpBanApiJsonContext.Default.ConnectionSnapshotContract,
                        cancellationToken).ConfigureAwait(false);
                }
                catch (JsonException)
                {
                    return Results.BadRequest(ApiResult<ConnectionTerminationContract>.Fail(
                        "INVALID_REQUEST",
                        "连接 JSON 无效。"));
                }

                if (body is null
                    || string.IsNullOrWhiteSpace(body.RemoteIp)
                    || body.RemotePort is null
                    || string.IsNullOrWhiteSpace(body.LocalIp)
                    || body.LocalPort is null)
                {
                    return Results.BadRequest(ApiResult<ConnectionTerminationContract>.Fail(
                        "INVALID_CONNECTION",
                        "连接端点不完整。"));
                }

                var result = await ManagementDisconnect.RunAsync(request.HttpContext, store, client, body, cancellationToken)
                    .ConfigureAwait(false);
                return Results.Ok(result);
            });

        return endpoints;
    }

    private static bool IsIpBanManagementConnection(ConnectionSnapshotContract connection) =>
        connection.LocalPort == 5180
        || connection.ProcessName?.Contains("IpBan.Api", StringComparison.OrdinalIgnoreCase) == true
        || connection.ProcessName?.Contains("IpBan.Agent", StringComparison.OrdinalIgnoreCase) == true;
}

public sealed record ManualBanHttpRequest(
    string SourceAddress,
    int DurationSeconds = ManualBanDuration.DefaultSeconds,
    bool DisconnectExisting = true,
    string? Reason = null);

public sealed record ManualUnbanHttpRequest(string SourceAddress, string ActionId);

[System.Text.Json.Serialization.JsonSourceGenerationOptions(
    PropertyNamingPolicy = System.Text.Json.Serialization.JsonKnownNamingPolicy.CamelCase)]
[System.Text.Json.Serialization.JsonSerializable(typeof(ManualBanHttpRequest))]
[System.Text.Json.Serialization.JsonSerializable(typeof(ManualUnbanHttpRequest))]
[System.Text.Json.Serialization.JsonSerializable(typeof(ConnectionSnapshotContract))]
internal sealed partial class IpBanApiJsonContext : System.Text.Json.Serialization.JsonSerializerContext
{
}
