using System.Globalization;
using System.Text.Json;
using System.Security.Cryptography;
using IpBan.Api.Service.impl;
using IpBan.Api.Models;
using IpBan.Shared.Logging;
using IpBan.Shared.Models;
using IpBan.Shared.Serialization;
using IpBan.Shared.Service;

namespace IpBan.Api.Service;

public static class ManagementEndpointExtensions
{
    public static IEndpointRouteBuilder MapManagementEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/admin/v1/overview", async (
            string? range,
            IAgentIpcClient client,
            SqliteAdminStore store,
            CancellationToken cancellationToken) =>
        {
            var connections = await client.ListConnectionsAsync(cancellationToken).ConfigureAwait(false);
            var events = await client.ListLoginEventsAsync(1000, cancellationToken).ConfigureAwait(false);
            var connectionData = connections.Data ?? Array.Empty<ConnectionSnapshotContract>();
            var eventData = events.Data ?? Array.Empty<LoginEventContract>();
            var sessions = CurrentSessionProjector.Project(connectionData, eventData);
            var firewall = await client.ProbeFirewallAsync(cancellationToken).ConfigureAwait(false);
            var overview = await store.GetOverviewAsync(
                connectionData.LongCount(item => !IsManagementConnection(item)),
                sessions.Count,
                firewall.Data?.Provider ?? "not-probed",
                firewall.Data?.Status ?? FirewallStatus.Unsupported,
                range,
                cancellationToken).ConfigureAwait(false);
            return Results.Ok(ApiResult<OverviewContract>.Ok(overview with { Host = OverviewHostReader.Read() }));
        });

        endpoints.MapGet("/api/admin/v1/users", async (SqliteAdminStore store, CancellationToken cancellationToken) =>
            Results.Ok(ApiResult<UserSummaryContract[]>.Ok((await store.ListUsersAsync(cancellationToken).ConfigureAwait(false)).ToArray())));

        endpoints.MapPut("/api/admin/v1/users/{id:long?}", async (
            long? id,
            HttpRequest request,
            SqliteAdminStore store,
            CancellationToken cancellationToken) =>
        {
            var body = await JsonSerializer.DeserializeAsync(request.Body, ManagementJsonContext.Default.UpsertUserRequest, cancellationToken).ConfigureAwait(false);
            if (body is null || string.IsNullOrWhiteSpace(body.Username) || string.IsNullOrWhiteSpace(body.DisplayName))
            {
                return Results.BadRequest(ApiResult<UserSummaryContract>.Fail("INVALID_USER", "用户名和显示名称不能为空。"));
            }

            try
            {
                var user = await store.UpsertUserAsync(id, body, ManagementAuditContext.From(request.HttpContext), "user.upsert", cancellationToken).ConfigureAwait(false);
                return Results.Ok(ApiResult<UserSummaryContract>.Ok(user));
            }
            catch (ArgumentException exception)
            {
                return Results.BadRequest(ApiResult<UserSummaryContract>.Fail("INVALID_USER", exception.Message));
            }
            catch (KeyNotFoundException exception)
            {
                return Results.NotFound(ApiResult<UserSummaryContract>.Fail("USER_NOT_FOUND", exception.Message));
            }
            catch (Microsoft.Data.Sqlite.SqliteException exception) when (exception.SqliteErrorCode == 19)
            {
                return Results.Conflict(ApiResult<UserSummaryContract>.Fail("USERNAME_EXISTS", "用户名已存在。"));
            }
        });

        endpoints.MapGet("/api/admin/v1/settings", async (SqliteAdminStore store, CancellationToken cancellationToken) =>
            Results.Ok(ApiResult<SystemSettingContract[]>.Ok((await store.ListSettingsAsync(cancellationToken).ConfigureAwait(false)).ToArray())));

        endpoints.MapPut("/api/admin/v1/settings/{key}", async (
            string key,
            HttpRequest request,
            SqliteAdminStore store,
            CancellationToken cancellationToken) =>
        {
            if (key.StartsWith("notifications.", StringComparison.OrdinalIgnoreCase))
            {
                return Results.Json(ApiResult<string>.Fail("NOTIFICATION_SETTINGS_RESERVED", "请通过通知设置页面修改此设置。"),
                    IpBanJsonContext.Default.ApiResultString, statusCode: StatusCodes.Status400BadRequest);
            }
            if (key.StartsWith("syslog.", StringComparison.OrdinalIgnoreCase))
            {
                return Results.Json(ApiResult<string>.Fail("SYSLOG_SETTINGS_RESERVED", "请通过 Syslog 配置页面修改此设置。"),
                    IpBanJsonContext.Default.ApiResultString, statusCode: StatusCodes.Status400BadRequest);
            }
            if (key.Equals(IpLocationService.SettingKey, StringComparison.OrdinalIgnoreCase))
            {
                return Results.Json(ApiResult<string>.Fail("IP_LOCATION_SETTINGS_RESERVED", "请通过 IP 数据库配置页面修改此设置。"),
                    IpBanJsonContext.Default.ApiResultString, statusCode: StatusCodes.Status400BadRequest);
            }
            if (string.IsNullOrWhiteSpace(key) || key.Length > 128)
            {
                return Results.BadRequest(ApiResult<SystemSettingContract>.Fail("INVALID_SETTING_KEY", "配置键无效。"));
            }

            UpdateSystemSettingRequest? body;
            try
            {
                body = await JsonSerializer.DeserializeAsync(
                    request.Body,
                    ManagementJsonContext.Default.UpdateSystemSettingRequest,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (JsonException)
            {
                return Results.BadRequest(ApiResult<SystemSettingContract>.Fail("INVALID_REQUEST", "请求 JSON 无效。"));
            }

            if (body is null)
            {
                return Results.BadRequest(ApiResult<SystemSettingContract>.Fail("INVALID_REQUEST", "请求内容不能为空。"));
            }

            var audit = ManagementAuditContext.From(request.HttpContext);
            await store.UpsertSettingAsync(key, body.IsSecret ? null : body.Value, body.IsSecret, audit.Actor, audit, cancellationToken).ConfigureAwait(false);
            var settings = await store.ListSettingsAsync(cancellationToken).ConfigureAwait(false);
            var setting = settings.First(item => item.Key.Equals(key, StringComparison.Ordinal));
            return Results.Ok(ApiResult<SystemSettingContract>.Ok(setting));
        });

        endpoints.MapGet("/api/admin/v1/audit", async (int? limit, SqliteAdminStore store, CancellationToken cancellationToken) =>
            Results.Ok(ApiResult<AuditRecordContract[]>.Ok((await store.ListAuditAsync(limit ?? 100, cancellationToken).ConfigureAwait(false)).ToArray())));

        endpoints.MapGet("/api/admin/v1/backups", async (int? limit, SqliteAdminStore store, CancellationToken cancellationToken) =>
            Results.Ok(ApiResult<BackupRecordContract[]>.Ok((await store.ListBackupsAsync(limit ?? 100, cancellationToken).ConfigureAwait(false)).ToArray())));

        endpoints.MapGet("/api/admin/v1/access-list", async (SqliteAdminStore store, CancellationToken cancellationToken) =>
            Results.Ok(ApiResult<AccessListEntryContract[]>.Ok((await store.ListAccessListAsync(cancellationToken).ConfigureAwait(false)).ToArray())));

        endpoints.MapPut("/api/admin/v1/access-list/{id:long?}", async (long? id, HttpRequest request, SqliteAdminStore store, CancellationToken cancellationToken) =>
        {
            var body = await JsonSerializer.DeserializeAsync(request.Body, ManagementJsonContext.Default.UpsertAccessListEntryRequest, cancellationToken).ConfigureAwait(false);
            if (body is null || string.IsNullOrWhiteSpace(body.Address) || string.IsNullOrWhiteSpace(body.EntryType))
                return Results.BadRequest(ApiResult<AccessListEntryContract>.Fail("INVALID_ACCESS_LIST_ENTRY", "地址和条目类型不能为空。"));
            var entry = await store.UpsertAccessListAsync(id, body, ManagementAuditContext.From(request.HttpContext), cancellationToken).ConfigureAwait(false);
            return Results.Ok(ApiResult<AccessListEntryContract>.Ok(entry));
        });

        endpoints.MapDelete("/api/admin/v1/access-list/{id:long}", async (long id, HttpContext context, SqliteAdminStore store, CancellationToken cancellationToken) =>
        {
            var deleted = await store.DeleteAccessListAsync(id, ManagementAuditContext.From(context), cancellationToken).ConfigureAwait(false);
            if (!deleted)
            {
                return Results.NotFound(ApiResult<object?>.Fail("ACCESS_LIST_NOT_FOUND", "名单条目不存在。"));
            }

            return Results.Ok(ApiResult<object?>.Ok(null, "名单条目已删除。"));
        });

        endpoints.MapGet("/api/admin/v1/policies", async (SqliteAdminStore store, CancellationToken cancellationToken) =>
            Results.Ok(ApiResult<BanPolicyContract[]>.Ok((await store.ListPoliciesAsync(cancellationToken).ConfigureAwait(false)).ToArray())));

        endpoints.MapPut("/api/admin/v1/policies/{id:long?}", async (long? id, HttpRequest request, SqliteAdminStore store, CancellationToken cancellationToken) =>
        {
            UpsertBanPolicyRequest? body;
            try
            {
                body = await JsonSerializer.DeserializeAsync(request.Body, ManagementJsonContext.Default.UpsertBanPolicyRequest, cancellationToken).ConfigureAwait(false);
            }
            catch (JsonException exception)
            {
                // 包含整数溢出、小数和空值；格式错误同样使用统一合同返回400，禁止落库。
                return Results.BadRequest(BanPolicyRequestValidator.InvalidJson(exception));
            }

            if (BanPolicyRequestValidator.Validate(body) is { } error)
                return Results.BadRequest(error);

            var policy = await store.UpsertPolicyAsync(id, body!, ManagementAuditContext.From(request.HttpContext), cancellationToken).ConfigureAwait(false);
            return Results.Ok(ApiResult<BanPolicyContract>.Ok(policy));
        });

        endpoints.MapDelete("/api/admin/v1/policies/{id:long}", async (long id, HttpContext context, SqliteAdminStore store, CancellationToken cancellationToken) =>
        {
            var deleted = await store.DeletePolicyAsync(id, ManagementAuditContext.From(context), cancellationToken).ConfigureAwait(false);
            if (!deleted)
            {
                return Results.NotFound(ApiResult<object?>.Fail("BAN_POLICY_NOT_FOUND", "自动封禁策略不存在。"));
            }

            return Results.Ok(ApiResult<object?>.Ok(null, "自动封禁策略已删除。"));
        });

        endpoints.MapGet("/api/admin/v1/firewall-actions", async (string? status, int? limit, SqliteAdminStore store, CancellationToken cancellationToken) =>
            Results.Ok(ApiResult<FirewallActionContract[]>.Ok((await store.ListFirewallActionsAsync(status, limit ?? 200, cancellationToken).ConfigureAwait(false)).ToArray())));

        endpoints.MapPost("/api/admin/v1/backups", async (HttpContext context, SqliteAdminStore store, CancellationToken cancellationToken) =>
        {
            var backup = await store.CreateBackupAsync(cancellationToken).ConfigureAwait(false);
            var audit = ManagementAuditContext.From(context);
            await store.AppendAuditAsync("backup.create", "backup", backup.BackupPath, null, audit.RemoteIp, true, audit.Actor,
                audit.TraceId, cancellationToken: cancellationToken).ConfigureAwait(false);
            return Results.Ok(ApiResult<BackupRecordContract>.Ok(backup));
        });

        endpoints.MapGet("/api/admin/v1/certificates", async (SqliteAdminStore store, CancellationToken cancellationToken) =>
            Results.Ok(ApiResult<CertificateMetadataContract[]>.Ok((await store.ListCertificatesAsync(cancellationToken).ConfigureAwait(false)).ToArray())));

        endpoints.MapPost("/api/admin/v1/certificates/upload", async (HttpRequest request, SqliteAdminStore store, CancellationToken cancellationToken) =>
        {
            var form = await request.ReadFormAsync(cancellationToken).ConfigureAwait(false);
            var file = form.Files.GetFile("certificate") ?? form.Files.GetFile("file");
            if (file is null || file.Length == 0)
            {
                return Results.BadRequest(ApiResult<CertificateMetadataContract>.Fail("CERTIFICATE_REQUIRED", "请上传包含私钥的 PFX 证书文件。"));
            }

            try
            {
                await using var stream = file.OpenReadStream();
                var metadata = await store.UploadPfxAsync(stream, cancellationToken).ConfigureAwait(false);
                var audit = ManagementAuditContext.From(request.HttpContext);
                await store.AppendAuditAsync("certificate.upload", "certificate", metadata.Thumbprint, null, audit.RemoteIp, true,
                    audit.Actor, audit.TraceId, cancellationToken: cancellationToken).ConfigureAwait(false);
                return Results.Ok(ApiResult<CertificateMetadataContract>.Ok(metadata, "证书已保存，重启 API 后生效。"));
            }
            catch (CryptographicException)
            {
                return Results.BadRequest(ApiResult<CertificateMetadataContract>.Fail("CERTIFICATE_INVALID", "证书格式无效。"));
            }
        });

        endpoints.MapGet("/api/admin/v1/logs/files", (FileLogStore store) =>
            Results.Ok(ApiResult<FileLogFileInfo[]>.Ok(store.ListFiles().ToArray())));

        endpoints.MapDelete("/api/admin/v1/logs/files/{fileName}", DeleteLogFileAsync);

        endpoints.MapGet("/api/admin/v1/logs", (string? fileName, string? keyword, int? limit, int? severity, string? appName, FileLogStore store) =>
            Results.Ok(ApiResult<string[]>.Ok(store.ReadLines(fileName, keyword, limit ?? 200, severity, appName).ToArray())));

        endpoints.MapGet("/api/admin/v1/logs/export", async (string? fileName, string? keyword, int? limit, int? severity, string? appName,
            HttpContext context, FileLogStore logs, SqliteAdminStore store, CancellationToken cancellationToken) =>
        {
            var content = string.Join(Environment.NewLine, logs.ReadLines(fileName, keyword, limit ?? 5000, severity, appName));
            await store.AppendAuditAsync("logs.export", "logs", null, null, context.Connection.RemoteIpAddress?.ToString(), true,
                context.Items["ipban.user"] as string, context.TraceIdentifier, cancellationToken: cancellationToken).ConfigureAwait(false);
            return Results.Text(content, "application/x-ndjson");
        });

        return endpoints;
    }

    private static bool IsManagementConnection(ConnectionSnapshotContract connection) =>
        connection.LocalPort == 5180
        || connection.ProcessName?.Contains("IpBan.", StringComparison.OrdinalIgnoreCase) == true;

    private static async Task<IResult> DeleteLogFileAsync(string fileName, HttpContext context,
        FileLogStore logs, SqliteAdminStore store, CancellationToken cancellationToken)
    {
        // 复用管理会话中间件写入的真实身份，禁止以默认管理员名代替缺失鉴权。
        var actor = context.Items["ipban.user"] as string;
        if (string.IsNullOrWhiteSpace(actor))
            return LogDeleteResponse(401, ApiResult<string>.Fail("AUTH_REQUIRED", "请先登录管理台。"));
        var target = FileLogStore.GetAuditTarget(fileName);
        var remoteIp = context.Connection.RemoteIpAddress?.ToString();
        try
        {
            await store.AppendAuditAsync("logs.file.delete.request", "logs", target, null, remoteIp, true,
                actor, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is Microsoft.Data.Sqlite.SqliteException or IOException or UnauthorizedAccessException)
        {
            return LogDeleteResponse(503, ApiResult<string>.Fail("LOG_DELETE_AUDIT_UNAVAILABLE", "审计记录暂不可用，未执行日志删除。"));
        }

        var deletion = logs.DeleteFile(fileName);
        var (status, code, message) = deletion switch
        {
            FileLogDeleteStatus.Deleted => (200, "OK", "日志文件已删除。"),
            FileLogDeleteStatus.InvalidName => (400, "LOG_FILE_INVALID", "请选择有效的本系统轮转日志文件。"),
            FileLogDeleteStatus.Protected => (409, "LOG_FILE_PROTECTED", "日常写入日志受保护，只能删除已轮转归档。"),
            FileLogDeleteStatus.NotFound => (404, "LOG_FILE_NOT_FOUND", "日志文件不存在，请刷新列表。"),
            FileLogDeleteStatus.Unsafe => (409, "LOG_FILE_UNSAFE", "该文件不是可删除的常规日志归档。"),
            _ => (409, "LOG_FILE_BUSY", "日志文件正在使用或暂时不可操作，请稍后重试。")
        };
        try
        {
            // 执行之后即使浏览器断开也完成结果审计；只写固定结果码，不泄漏路径或异常内容。
            await store.AppendAuditAsync("logs.file.delete", "logs", target,
                "{\"code\":\"" + code + "\"}", remoteIp, deletion == FileLogDeleteStatus.Deleted,
                actor, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is Microsoft.Data.Sqlite.SqliteException or IOException or UnauthorizedAccessException)
        {
            return LogDeleteResponse(503, ApiResult<string>.Fail("LOG_DELETE_AUDIT_FAILED",
                "操作结果审计写入失败，请刷新列表确认实际状态，勿重复提交。"));
        }

        return LogDeleteResponse(status, new ApiResult<string>(deletion == FileLogDeleteStatus.Deleted, code, message, null));
    }

    private static IResult LogDeleteResponse(int status, ApiResult<string> result) =>
        Results.Json(result, IpBanJsonContext.Default.ApiResultString, statusCode: status);
}

public sealed record UpdateSystemSettingRequest(string? Value, bool IsSecret = false);

public sealed record UpsertUserRequest(
    string Username,
    string DisplayName,
    string? Password = null,
    bool Enabled = true);

public sealed record LoginAccountRequest(
    string Username,
    string Password,
    string? Type = "account");

public sealed record UpsertAccessListEntryRequest(
    string Address,
    string EntryType,
    string Source = "Manual",
    string? Reason = null,
    int Priority = 100,
    string Status = "Active",
    string? CreatedBy = "local-admin",
    DateTimeOffset? EffectiveAtUtc = null,
    DateTimeOffset? ExpiresAtUtc = null);

public sealed record UpsertBanPolicyRequest(
    string Name,
    bool Enabled = true,
    int Threshold = 5,
    int WindowSeconds = 300,
    int ObserveSeconds = 0,
    int CooldownSeconds = 900,
    int BanDurationSeconds = 1800,
    string Action = "Ban",
    string? Protocol = null,
    string? Description = null);

[System.Text.Json.Serialization.JsonSourceGenerationOptions(
    PropertyNamingPolicy = System.Text.Json.Serialization.JsonKnownNamingPolicy.CamelCase)]
[System.Text.Json.Serialization.JsonSerializable(typeof(UpdateSystemSettingRequest))]
[System.Text.Json.Serialization.JsonSerializable(typeof(UpsertUserRequest))]
[System.Text.Json.Serialization.JsonSerializable(typeof(LoginAccountRequest))]
[System.Text.Json.Serialization.JsonSerializable(typeof(UpsertAccessListEntryRequest))]
[System.Text.Json.Serialization.JsonSerializable(typeof(UpsertBanPolicyRequest))]
internal sealed partial class ManagementJsonContext : System.Text.Json.Serialization.JsonSerializerContext
{
}
