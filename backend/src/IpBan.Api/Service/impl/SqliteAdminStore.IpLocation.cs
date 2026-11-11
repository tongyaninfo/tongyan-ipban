using System.Globalization;
using Microsoft.Data.Sqlite;

namespace IpBan.Api.Service.impl;

public sealed partial class SqliteAdminStore
{
    public async Task<string?> GetIpLocationSettingsAsync(CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT setting_value FROM system_settings WHERE setting_key=$key AND is_secret=0;";
        command.Parameters.AddWithValue("$key", IpLocationService.SettingKey);
        return await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as string;
    }

    /// <summary>配置和可靠审计同事务提交，审计不可用时不生效也不假报成功。</summary>
    public async Task SaveIpLocationSettingsAsync(string json, string actor, string? remoteIp, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO system_settings(setting_key,setting_value,is_secret,updated_at_utc,updated_by) VALUES($key,$value,0,$now,$actor) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,is_secret=0,updated_at_utc=excluded.updated_at_utc,updated_by=excluded.updated_by;";
        command.Parameters.AddWithValue("$key", IpLocationService.SettingKey);
        command.Parameters.AddWithValue("$value", json);
        command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$actor", actor);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        await AppendAuditCoreAsync(connection, transaction, "ip-location.settings.update", "settings", IpLocationService.SettingKey,
            null, remoteIp, true, actor, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        PublishAudit("ip-location.settings.update", null, actor, remoteIp);
    }
}
