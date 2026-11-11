using System.Globalization;
using System.Text.Json;
using IpBan.Shared.Logging.Syslog;
using IpBan.Shared.Service;
using Microsoft.Data.Sqlite;

namespace IpBan.Api.Service.impl;

public sealed partial class SqliteAdminStore
{
    public async Task<SyslogSettings> ReadSyslogSettingsAsync(CancellationToken cancellationToken)
    {
        // 配置轮询只读取既有数据库，不在 Agent 尚未初始化时创建空文件。
        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = SqliteOpenMode.ReadOnly,
            DefaultTimeout = 2
        }.ToString());
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await ReadSyslogSettingsAsync(connection, null, cancellationToken).ConfigureAwait(false);
    }

    public async Task<SyslogSettings> SaveSyslogSettingsAsync(SyslogSettings settings, string actor, string? remoteIp,
        IIdService ids, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction(deferred: false);
        var current = await ReadSyslogSettingsAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(current.ConfigRevision, settings.ConfigRevision, StringComparison.Ordinal))
            throw new SyslogRequestException(409, "SYSLOG_SETTINGS_CHANGED", "Syslog 配置已被修改，请刷新后重新提交。");

        var existingTargets = (current.Targets ?? []).ToDictionary(target => target.Id, StringComparer.Ordinal);
        var usedIds = new HashSet<string>(StringComparer.Ordinal);
        var targets = new List<SyslogTarget>();
        foreach (var target in settings.Targets ?? [])
        {
            var existing = string.IsNullOrEmpty(target.Id) ? null : existingTargets.GetValueOrDefault(target.Id);
            if (existing is not null && !usedIds.Add(existing.Id))
                throw new SyslogRequestException(400, "INVALID_SYSLOG_SETTINGS", "同一个 Syslog 目标不能重复提交。");
            // 客户端只能引用现有目标。删除后重新添加同地址应使用新队列。
            var id = existing?.Id ?? ids.NewId.ToString(CultureInfo.InvariantCulture);
            var version = existing is not null && SameDelivery(existing, target)
                ? existing.DeliveryTargetVersion : ids.NewId.ToString(CultureInfo.InvariantCulture);
            targets.Add(target with { Id = id, DeliveryTargetVersion = version });
        }

        var updated = settings with
        {
            ConfigRevision = ids.NewId.ToString(CultureInfo.InvariantCulture),
            Targets = targets.ToArray()
        };
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO system_settings(setting_key, setting_value, is_secret, updated_at_utc, updated_by)
            VALUES ($key, $value, 0, $now, $actor)
            ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,
                is_secret=0, updated_at_utc=excluded.updated_at_utc, updated_by=excluded.updated_by;
            """;
        command.Parameters.AddWithValue("$key", SyslogConfiguration.SettingKey);
        command.Parameters.AddWithValue("$value", JsonSerializer.Serialize(updated, SyslogJsonContext.Default.SyslogSettings));
        command.Parameters.AddWithValue("$now", now.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$actor", actor);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // 只审计安全选项数量和版本，避免外发服务器列表。
        var ignoreCount = targets.Count(target => target.IgnoreSslErrors);
        var detail = FormattableString.Invariant($$"""{"ignoreSslErrorsTargets":{{ignoreCount}}}""");
        await AppendAuditCoreAsync(connection, transaction, "syslog.settings.update", "syslog", updated.ConfigRevision,
            detail, remoteIp, true, actor, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return updated;
    }

    private static async Task<SyslogSettings> ReadSyslogSettingsAsync(SqliteConnection connection, SqliteTransaction? transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT setting_value FROM system_settings WHERE setting_key=$key AND is_secret=0;";
        command.Parameters.AddWithValue("$key", SyslogConfiguration.SettingKey);
        var value = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        if (value is null) return new SyslogSettings(Targets: []);

        SyslogSettings? candidate;
        try { candidate = value is string json ? JsonSerializer.Deserialize(json, SyslogJsonContext.Default.SyslogSettings) : null; }
        catch (JsonException) { throw new InvalidDataException("已保存的 Syslog 配置无效。"); }
        if (candidate is null || !ValidKey(candidate.ConfigRevision)
            || !SyslogConfiguration.TryNormalize(candidate, out var settings, out _)
            || settings.Targets!.Any(target => !ValidKey(target.Id) || !ValidKey(target.DeliveryTargetVersion))
            || settings.Targets!.Select(target => target.Id).Distinct(StringComparer.Ordinal).Count() != settings.Targets!.Length)
            throw new InvalidDataException("已保存的 Syslog 配置无效。");
        return settings;
    }

    private static bool ValidKey(string? value) => value is { Length: > 0 and <= 64 }
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');

    private static bool SameDelivery(SyslogTarget left, SyslogTarget right) =>
        string.Equals(left.Host, right.Host, StringComparison.OrdinalIgnoreCase) && left.Port == right.Port
        && left.Protocol == right.Protocol
        && left.IgnoreSslErrors == right.IgnoreSslErrors && left.Framing == right.Framing;
}
