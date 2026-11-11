using System.Globalization;
using IpBan.Shared.Logging.Syslog;
using IpBan.Shared.Models;
using IpBan.Shared.Service;
using Microsoft.Data.Sqlite;

namespace IpBan.Agent.Service.impl;

public sealed class SqliteLoginEventStore(ISqliteConnectionFactory connectionFactory, SyslogRuntime? syslog = null) : ILoginEventStore
{
    public async Task AppendAsync(LoginEventContract loginEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(loginEvent);

        await using var connection = await connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        // 单条 SQL 原子检查证据，复用来源/时间索引避免每次重放扫描一年的历史。
        // 不以用户名或端点去重，不同原始 ID 的独立认证必须各自参与阈值统计。
        command.CommandText =
            """
            INSERT INTO login_events (
                id, occurred_at_utc, protocol, is_success, username, remote_ip, remote_ip_availability, remote_port,
                local_ip, local_port, local_process_id, local_process_name, origin_process_id,
                origin_process_name, completeness_level, username_availability, endpoint_availability,
                process_availability, collector, raw_event_id, evidence_source)
            SELECT
                $id, $occurredAtUtc, $protocol, $isSuccess, $username, $remoteIp, $remoteIpAvailability, $remotePort,
                $localIp, $localPort, $localProcessId, $localProcessName, $originProcessId,
                $originProcessName, $completenessLevel, $usernameAvailability, $endpointAvailability,
                $processAvailability, $collector, $rawEventId, $evidenceSource
            WHERE $rawEventId IS NULL OR NOT EXISTS (
                SELECT 1 FROM login_events
                WHERE remote_ip IS $remoteIp AND occurred_at_utc = $occurredAtUtc
                    AND collector = $collector AND raw_event_id = $rawEventId);
            """;
        Add(command, "$id", loginEvent.Id);
        Add(command, "$occurredAtUtc", loginEvent.OccurredAtUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        Add(command, "$protocol", loginEvent.Protocol.ToString());
        Add(command, "$isSuccess", loginEvent.Success ? 1 : 0);
        Add(command, "$username", loginEvent.Username);
        Add(command, "$remoteIp", loginEvent.RemoteIp);
        Add(command, "$remoteIpAvailability", loginEvent.RemoteIpAvailability.ToString());
        Add(command, "$remotePort", loginEvent.RemotePort);
        Add(command, "$localIp", loginEvent.LocalIp);
        Add(command, "$localPort", loginEvent.LocalPort);
        Add(command, "$localProcessId", loginEvent.LocalProcessId);
        Add(command, "$localProcessName", loginEvent.LocalProcessName);
        Add(command, "$originProcessId", loginEvent.OriginProcessId);
        Add(command, "$originProcessName", loginEvent.OriginProcessName);
        Add(command, "$completenessLevel", loginEvent.CompletenessLevel.ToString());
        Add(command, "$usernameAvailability", loginEvent.UsernameAvailability.ToString());
        Add(command, "$endpointAvailability", loginEvent.EndpointAvailability.ToString());
        Add(command, "$processAvailability", loginEvent.ProcessAvailability.ToString());
        Add(command, "$collector", loginEvent.Collector);
        Add(command, "$rawEventId", loginEvent.RawEventId);
        Add(command, "$evidenceSource", loginEvent.EvidenceSource);
        var inserted = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        if (inserted > 0)
        {
            // 原始证据重放可能插入零行，只有本次新增事件才生成通知候选。
            var snapshot = new NotificationEventSnapshot(loginEvent.Success ? "loginSuccess" : "loginFailure",
                loginEvent.Id.ToString(CultureInfo.InvariantCulture), Environment.MachineName, loginEvent.RemoteIp,
                loginEvent.Protocol.ToString(), loginEvent.Username, loginEvent.OccurredAtUtc,
                loginEvent.Success ? "Success" : "Failure", LocalIp: loginEvent.LocalIp);
            await SqliteNotificationEventWriter.AppendAsync(connection, transaction, $"login:{snapshot.SourceId}", snapshot, cancellationToken).ConfigureAwait(false);
        }
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        if (inserted > 0)
            syslog?.Publish("ipban-login", loginEvent.Success ? "host.login.success" : "host.login.failure",
                loginEvent.Success ? SyslogSeverity.Notice : SyslogSeverity.Emergency,
                loginEvent.Success ? "主机登录成功。" : "主机登录失败。",
                result: loginEvent.Success ? "Success" : "Failure",
                sourceId: loginEvent.Id.ToString(CultureInfo.InvariantCulture), remoteIp: loginEvent.RemoteIp,
                actor: loginEvent.Username, protocol: loginEvent.Protocol.ToString(), occurredAtUtc: loginEvent.OccurredAtUtc);
    }

    public async Task<IReadOnlyList<LoginEventContract>> QueryRecentAsync(
        int limit = 100,
        CancellationToken cancellationToken = default)
    {
        var boundedLimit = Math.Clamp(limit, 1, 1000);
        await using var connection = await connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT id, occurred_at_utc, protocol, is_success, username, remote_ip,
                   remote_ip_availability, remote_port,
                   local_ip, local_port, local_process_id, local_process_name, origin_process_id,
                   origin_process_name, completeness_level, username_availability, endpoint_availability,
                   process_availability, collector, raw_event_id, evidence_source
            FROM login_events
            ORDER BY occurred_at_utc DESC, id DESC
            LIMIT $limit;
            """;
        Add(command, "$limit", boundedLimit);

        var results = new List<LoginEventContract>(boundedLimit);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            results.Add(ReadEvent(reader));
        }

        return results;
    }

    private static LoginEventContract ReadEvent(SqliteDataReader reader) => new(
        Id: reader.GetInt64(0),
        OccurredAtUtc: ParseTimestamp(reader.GetString(1)),
        Protocol: ParseEnum<ProtocolKind>(LoginEventProtocol.ResolveStored(
            reader.GetString(2), reader.GetString(20), GetNullableString(reader, 11))),
        Success: reader.GetInt64(3) != 0,
        Username: GetNullableString(reader, 4),
        RemoteIp: GetNullableString(reader, 5),
        RemotePort: GetNullableInt32(reader, 7),
        LocalIp: GetNullableString(reader, 8),
        LocalPort: GetNullableInt32(reader, 9),
        LocalProcessId: GetNullableInt32(reader, 10),
        LocalProcessName: GetNullableString(reader, 11),
        OriginProcessId: GetNullableInt32(reader, 12),
        OriginProcessName: GetNullableString(reader, 13),
        CompletenessLevel: ParseEnum<EventCompletenessLevel>(reader.GetString(14)),
        UsernameAvailability: ParseEnum<FieldAvailability>(reader.GetString(15)),
        RemoteIpAvailability: ParseEnum<FieldAvailability>(reader.GetString(6)),
        EndpointAvailability: ParseEnum<FieldAvailability>(reader.GetString(16)),
        ProcessAvailability: ParseEnum<FieldAvailability>(reader.GetString(17)),
        Collector: reader.GetString(18),
        RawEventId: GetNullableString(reader, 19),
        EvidenceSource: reader.GetString(20));

    private static DateTimeOffset ParseTimestamp(string value) =>
        DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind).ToUniversalTime();

    private static TEnum ParseEnum<TEnum>(string value)
        where TEnum : struct, Enum => Enum.TryParse<TEnum>(value, ignoreCase: false, out var result)
            ? result
            : throw new InvalidDataException($"数据库中存在未知的 {typeof(TEnum).Name} 值：{value}");

    private static string? GetNullableString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static int? GetNullableInt32(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetInt32(ordinal);

    private static void Add(SqliteCommand command, string name, object? value) =>
        command.Parameters.AddWithValue(name, value ?? DBNull.Value);
}
