using System.Text.Json;
using IpBan.Shared.Logging.Syslog;
using Microsoft.Data.Sqlite;

namespace IpBan.Agent.Service.impl;

internal sealed class AgentSyslogSettingsReader(ISqliteConnectionFactory factory) : ISyslogSettingsReader
{
    public async Task<SyslogSettings> ReadAsync(CancellationToken cancellationToken)
    {
        // 刷新只读现有配置，避免数据库尚未初始化时创建空库或改变结构。
        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = factory.DatabasePath,
            Mode = SqliteOpenMode.ReadOnly,
            DefaultTimeout = 2
        }.ToString());
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT setting_value FROM system_settings WHERE setting_key=$key AND is_secret=0;";
        command.Parameters.AddWithValue("$key", SyslogConfiguration.SettingKey);
        var value = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return value is string json
            ? JsonSerializer.Deserialize(json, SyslogJsonContext.Default.SyslogSettings)
                ?? throw new InvalidDataException("Syslog 配置内容为空。")
            : new SyslogSettings();
    }
}
