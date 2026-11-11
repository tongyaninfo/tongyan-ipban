using System.Data;
using System.Globalization;
using System.Net;
using System.Text.Json;
using IpBan.Shared.Models;
using IpBan.Shared.Service;
using IpBan.Shared.Logging.Syslog;
using Microsoft.Data.Sqlite;
using MimeKit;

namespace IpBan.Api.Service.impl;

/// <summary>通知配置与投递编排。凭据仅在发送时解密，配置、测试操作与可靠审计同事务提交。</summary>
public sealed partial class NotificationService(SqliteAdminStore store, NotificationCredentialProtector protector,
    NotificationTemplateRenderer renderer, INotificationEmailSender sender, IIdService ids, TimeProvider clock,
    SyslogRuntime? syslog = null) : IDisposable
{
    public const string SettingKey = "notifications.settings";
    public const string CredentialKey = "notifications.credential";
    private readonly SemaphoreSlim gate = new(1, 1);
    private static readonly string[] EventTypes = ["loginSuccess", "loginFailure", "ban", "unban"];

    public async Task<NotificationSettings> GetSettingsAsync(CancellationToken ct)
    {
        await using var db = await store.OpenNotificationConnectionAsync(ct).ConfigureAwait(false);
        return (await ReadConfigurationAsync(db, null, ct).ConfigureAwait(false)).Settings;
    }

    public async Task<NotificationSettings> SaveSettingsAsync(UpdateNotificationSettingsRequest request, string actor, string? remoteIp, CancellationToken ct)
    {
        if (!TryValidate(request.Settings, out var normalized, out var message)) throw new NotificationRequestException(400, "INVALID_NOTIFICATION_SETTINGS", message);
        if (request.Credential?.Length > 4096 || request.ClearCredential && !string.IsNullOrEmpty(request.Credential))
            throw new NotificationRequestException(400, "INVALID_NOTIFICATION_CREDENTIAL", "授权码长度或更新方式无效。");
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await using var db = await store.OpenNotificationConnectionAsync(ct).ConfigureAwait(false);
            await using var tx = db.BeginTransaction();
            var current = await ReadConfigurationAsync(db, tx, ct).ConfigureAwait(false);
            if (!string.Equals(current.Settings.Revision, normalized.Revision, StringComparison.Ordinal))
                throw new NotificationRequestException(409, "NOTIFICATION_SETTINGS_CHANGED", "通知设置已被其他操作修改，请刷新后重试。");
            var encrypted = request.ClearCredential ? null : current.Credential;
            if (!string.IsNullOrEmpty(request.Credential)) encrypted = protector.Protect(request.Credential, allowCreateMasterKey: current.Credential is null);
            if (normalized.Enabled && encrypted is null)
                throw new NotificationRequestException(400, "NOTIFICATION_CREDENTIAL_REQUIRED", "启用通知前请设置邮箱授权码。");
            var now = clock.GetUtcNow();
            normalized = normalized with { HasCredential = encrypted is not null, Revision = ids.NewId.ToString(CultureInfo.InvariantCulture),
                EnabledSinceUtc = normalized.Enabled ? current.Settings.EnabledSinceUtc ?? now : null };
            // 每次变更快照都取消旧配置下尚未发送的任务，防止换收件人后投递旧任务。
            await ExecuteAsync(db, tx, "UPDATE notification_events SET status='cancelled' WHERE status='pending'; UPDATE notification_outbox SET status='cancelled',next_attempt_at_utc=NULL WHERE status IN ('queued','retry');", ct).ConfigureAwait(false);
            await WriteSettingAsync(db, tx, SettingKey, JsonSerializer.Serialize(normalized, NotificationJsonContext.Default.NotificationSettings), false, actor, now, ct).ConfigureAwait(false);
            await WriteSettingAsync(db, tx, CredentialKey, encrypted, true, actor, now, ct).ConfigureAwait(false);
            await SqliteAdminStore.AppendNotificationAuditAsync(db, tx, "notifications.settings.update", SettingKey, actor, remoteIp, ct).ConfigureAwait(false);
            await tx.CommitAsync(ct).ConfigureAwait(false);
            store.PublishAudit("notifications.settings.update", normalized.Revision, actor, remoteIp);
            return normalized;
        }
        finally { gate.Release(); }
    }

    public static bool TryValidate(NotificationSettings? settings, out NotificationSettings normalized, out string message)
    {
        normalized = settings ?? new();
        message = "通知设置格式无效。";
        if (settings is null || settings.Host is null || settings.FromAddress is null || settings.Username is null || settings.FromName is null
            || settings.Recipients is null || settings.Rules is null || settings.Revision is null) return false;
        var host = settings.Host.Trim();
        var from = settings.FromAddress.Trim();
        var username = settings.Username.Trim();
        if (host.Length > 253 || host.Length > 0 && Uri.CheckHostName(host) == UriHostNameType.Unknown)
        { message = "SMTP 地址只能填写主机名或 IP，不能包含协议、路径或账号。"; return false; }
        if (settings.Port is < 1 or > 65535 || settings.Security is not ("ssl" or "starttls" or "none"))
        { message = "端口或加密方式无效。"; return false; }
        if (settings.FromName.Length > 80 || username.Length > 254 || HasControls(settings.FromName) || HasControls(username))
        { message = "发件人名称或登录账号长度、字符无效。"; return false; }
        if (from.Length > 0 && !IsMailbox(from) || settings.Recipients.Length > 10 || settings.Recipients.Any(value => !IsMailbox(value)))
        { message = "请填写有效邮箱，收件人最多 10 个。"; return false; }
        if (settings.MaxPerMinute is < 1 or > 120 || settings.MaxPerHour < settings.MaxPerMinute || settings.MaxPerHour > 10000
            || settings.RetryCount is < 0 or > 5 || settings.RetentionDays is < 1 or > 365 || settings.QueueLifetimeHours is < 1 or > 168)
        { message = "发送额度、重试次数或留存期限超出允许范围。"; return false; }
        if (settings.Rules.Length != 4 || settings.Rules.Any(rule => rule is null || !EventTypes.Contains(rule.EventType, StringComparer.Ordinal)
                || rule.IntervalSeconds is < 10 or > 86400) || settings.Rules.Select(rule => rule.EventType).Distinct(StringComparer.Ordinal).Count() != 4)
        { message = "必须配置四类通知，合并间隔为 10～86400 秒。"; return false; }
        if (settings.Enabled && (host.Length == 0 || from.Length == 0 || settings.Recipients.Length == 0))
        { message = "启用通知前请填写 SMTP 地址、发件邮箱和收件邮箱。"; return false; }
        normalized = settings with { Host = host, FromAddress = from, Username = username.Length == 0 ? from : username,
            FromName = settings.FromName.Trim(), Recipients = settings.Recipients.Select(value => value.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray() };
        message = "";
        return true;
    }

    public static bool IsMailbox(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 254 && !HasControls(value)
        && MailboxAddress.TryParse(value.Trim(), out var parsed) && string.Equals(parsed.Address, value.Trim(), StringComparison.Ordinal)
        && parsed.Address.Contains('@', StringComparison.Ordinal);
    private static bool HasControls(string value) => value.Any(char.IsControl);

    private static async Task<(NotificationSettings Settings, string? Credential)> ReadConfigurationAsync(SqliteConnection db, SqliteTransaction? tx, CancellationToken ct)
    {
        var json = await ScalarAsync(db, tx, "SELECT setting_value FROM system_settings WHERE setting_key=$key;", ct, ("$key", SettingKey)).ConfigureAwait(false) as string;
        var credential = await ScalarAsync(db, tx, "SELECT setting_value FROM system_settings WHERE setting_key=$key AND is_secret=1;", ct, ("$key", CredentialKey)).ConfigureAwait(false) as string;
        var settings = json is null ? new NotificationSettings() : JsonSerializer.Deserialize(json, NotificationJsonContext.Default.NotificationSettings)
            ?? throw new InvalidDataException("通知配置不可用。");
        return (settings with { HasCredential = credential is not null }, credential);
    }

    private static Task WriteSettingAsync(SqliteConnection db, SqliteTransaction tx, string key, string? value, bool secret, string actor, DateTimeOffset now, CancellationToken ct) =>
        ExecuteAsync(db, tx, "INSERT INTO system_settings(setting_key,setting_value,is_secret,updated_at_utc,updated_by) VALUES($key,$value,$secret,$now,$actor) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,is_secret=excluded.is_secret,updated_at_utc=excluded.updated_at_utc,updated_by=excluded.updated_by;", ct,
            ("$key", key), ("$value", value), ("$secret", secret ? 1 : 0), ("$now", Utc(now)), ("$actor", actor));

    private static SqliteCommand Command(SqliteConnection db, SqliteTransaction? tx, string sql, params (string Name, object? Value)[] args)
    {
        var cmd = db.CreateCommand(); cmd.Transaction = tx; cmd.CommandText = sql;
        foreach (var (name, value) in args) cmd.Parameters.AddWithValue(name, value ?? DBNull.Value);
        return cmd;
    }
    private static async Task ExecuteAsync(SqliteConnection db, SqliteTransaction? tx, string sql, CancellationToken ct, params (string Name, object? Value)[] args)
    { await using var cmd = Command(db, tx, sql, args); await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
    private static async Task<object?> ScalarAsync(SqliteConnection db, SqliteTransaction? tx, string sql, CancellationToken ct, params (string Name, object? Value)[] args)
    { await using var cmd = Command(db, tx, sql, args); return await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false); }
    private static async Task<long> CountAsync(SqliteConnection db, SqliteTransaction? tx, string sql, CancellationToken ct, params (string Name, object? Value)[] args)
        => Convert.ToInt64(await ScalarAsync(db, tx, sql, ct, args).ConfigureAwait(false), CultureInfo.InvariantCulture);
    private static string Utc(DateTimeOffset time) => time.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
    private static DateTimeOffset Parse(string value) => DateTimeOffset.Parse(value, CultureInfo.InvariantCulture);
    public void Dispose() => gate.Dispose();
}

public sealed class NotificationRequestException(int status, string code, string message) : Exception(message)
{
    public int Status { get; } = status;
    public string Code { get; } = code;
}
