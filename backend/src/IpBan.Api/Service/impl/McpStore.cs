using System.Globalization;
using System.Security.Cryptography;
using IpBan.Api.Models;
using IpBan.Shared.Service;
using Microsoft.Data.Sqlite;

namespace IpBan.Api.Service.impl;

public sealed class McpStoreException(string code, int httpStatus, string message) : Exception(message)
{
    public string Code { get; } = code;
    public int HttpStatus { get; } = httpStatus;
}

/// <summary>MCP 设置、凭据与独立调用审计的 SQLite 持久化。</summary>
public sealed class McpStore(SqliteAdminStore adminStore, McpKeyProtector protector, IIdService ids)
{
    private const string KeySelect = """
        SELECT k.id, k.name, k.prefix, k.mode, k.created_at_utc, k.expires_at_utc, k.revoked_at_utc,
               (SELECT group_concat(scope, ',') FROM (SELECT scope FROM mcp_api_key_scopes WHERE key_id = k.id ORDER BY scope))
        FROM mcp_api_keys k
        """;
    private const string CallColumns = """
        id, occurred_at_utc, key_id, key_name, key_prefix, trace_id, remote_ip, method, tool, status, http_status, duration_ms
        """;

    public async Task<McpSettings> GetSettingsAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        return await ReadSettingsAsync(connection, null, cancellationToken).ConfigureAwait(false);
    }

    public async Task<McpSettings> UpdateSettingsAsync(bool? enabled, int? days, bool confirmShorter, string actor, string? remoteIp,
        CancellationToken cancellationToken = default)
    {
        if (days is < 1 or > 3650)
        {
            throw new McpStoreException("INVALID_RETENTION", 400, "留存天数必须是 1 到 3650 的整数。");
        }

        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        using var transaction = connection.BeginTransaction(deferred: false);
        var current = await ReadSettingsAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
        var next = new McpSettings(enabled ?? current.Enabled, days ?? current.AuditRetentionDays);
        // 在写锁内读取现值，避免并发调整留存时绕过缩短确认或按旧值清理。
        if (next.AuditRetentionDays < current.AuditRetentionDays && !confirmShorter)
        {
            throw new McpStoreException("RETENTION_CONFIRMATION_REQUIRED", 409, "缩短留存期限将清理超期调用记录，请确认后保存。");
        }
        if (next != current)
        {
            await ExecuteAsync(connection, transaction, "UPDATE mcp_settings SET enabled = $enabled, audit_retention_days = $days WHERE id = 1;",
                cancellationToken, ("$enabled", next.Enabled ? 1 : 0), ("$days", next.AuditRetentionDays)).ConfigureAwait(false);
            if (next.Enabled != current.Enabled)
            {
                await WriteManagementAuditAsync(connection, transaction, next.Enabled ? "mcp.start" : "mcp.stop", null,
                    actor, remoteIp, null, cancellationToken).ConfigureAwait(false);
            }
            if (next.AuditRetentionDays != current.AuditRetentionDays)
            {
                var detail = FormattableString.Invariant($"{{\"oldDays\":{current.AuditRetentionDays},\"newDays\":{next.AuditRetentionDays}}}");
                await WriteManagementAuditAsync(connection, transaction, "mcp.retention.update", null, actor, remoteIp, detail,
                    cancellationToken).ConfigureAwait(false);
            }
        }
        transaction.Commit();
        if (next.Enabled != current.Enabled) adminStore.PublishAudit(next.Enabled ? "mcp.start" : "mcp.stop", null, actor, remoteIp);
        if (next.AuditRetentionDays != current.AuditRetentionDays) adminStore.PublishAudit("mcp.retention.update", null, actor, remoteIp);
        return next;
    }

    public async Task<McpApiKey[]> ListKeysAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = Command(connection, null, KeySelect + " ORDER BY k.created_at_utc DESC, k.id DESC;");
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var keys = new List<McpApiKey>();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            keys.Add(ReadKey(reader));
        }
        return [.. keys];
    }

    public async Task<McpCreatedKey> CreateKeyAsync(string name, bool canWrite, DateTimeOffset? expiresAtUtc,
        IReadOnlyCollection<string> scopes, string actor, string? remoteIp, CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        name = name.Trim();
        if (name.Length is < 1 or > 128 || expiresAtUtc <= now || scopes.Count == 0 || scopes.Any(scope =>
            string.IsNullOrWhiteSpace(scope) || scope.Contains(',', StringComparison.Ordinal)))
        {
            throw new McpStoreException("INVALID_MCP_KEY", 400, "请填写有效的名称、到期时间和授权工具。");
        }

        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        using var transaction = connection.BeginTransaction(deferred: false);
        await using var exists = Command(connection, transaction, "SELECT EXISTS (SELECT 1 FROM mcp_api_keys);");
        var allowCreateMaster = (long)(await exists.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) ?? 1L) == 0;
        var id = ids.NewId;
        var secret = "ipban_" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        var key = new McpApiKey(id, name, secret[..14], canWrite ? "write" : "read", now, expiresAtUtc?.ToUniversalTime(), null,
            [.. scopes.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)]);
        byte[] protectedSecret;
        try
        {
            protectedSecret = protector.Protect(id, secret, allowCreateMaster);
        }
        catch (Exception exception) when (exception is CryptographicException or IOException or UnauthorizedAccessException)
        {
            throw new McpStoreException("MCP_KEY_PROTECTION_UNAVAILABLE", 503, "MCP 加密密钥材料不可用，无法创建 Key。");
        }

        await ExecuteAsync(connection, transaction, """
            INSERT INTO mcp_api_keys(id, name, prefix, secret_hash, protected_secret, mode, created_at_utc, expires_at_utc)
            VALUES ($id, $name, $prefix, $hash, $secret, $mode, $created, $expires);
            """, cancellationToken, ("$id", key.Id), ("$name", key.Name), ("$prefix", key.Prefix),
            ("$hash", UserPasswordHasher.HashToken(secret)), ("$secret", protectedSecret), ("$mode", key.Mode),
            ("$created", Timestamp(key.CreatedAtUtc)), ("$expires", Timestamp(key.ExpiresAtUtc))).ConfigureAwait(false);
        foreach (var scope in key.Scopes)
        {
            await ExecuteAsync(connection, transaction, "INSERT INTO mcp_api_key_scopes(key_id, scope) VALUES ($id, $scope);",
                cancellationToken, ("$id", id), ("$scope", scope)).ConfigureAwait(false);
        }
        await WriteManagementAuditAsync(connection, transaction, "mcp.key.create", id, actor, remoteIp, null,
            cancellationToken).ConfigureAwait(false);
        transaction.Commit();
        adminStore.PublishAudit("mcp.key.create", id.ToString(CultureInfo.InvariantCulture), actor, remoteIp);
        return new McpCreatedKey(key, secret);
    }

    public Task<bool> RevokeKeyAsync(long id, string actor, string? remoteIp, CancellationToken cancellationToken = default) =>
        ChangeKeyAsync(id, actor, remoteIp, delete: false, cancellationToken);

    public Task<bool> DeleteKeyAsync(long id, string actor, string? remoteIp, CancellationToken cancellationToken = default) =>
        ChangeKeyAsync(id, actor, remoteIp, delete: true, cancellationToken);

    private async Task<bool> ChangeKeyAsync(long id, string actor, string? remoteIp, bool delete, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        using var transaction = connection.BeginTransaction(deferred: false);
        var changed = delete
            ? await ExecuteAsync(connection, transaction, "DELETE FROM mcp_api_keys WHERE id = $id AND revoked_at_utc IS NOT NULL;",
                cancellationToken, ("$id", id)).ConfigureAwait(false)
            : await ExecuteAsync(connection, transaction, "UPDATE mcp_api_keys SET revoked_at_utc = $now WHERE id = $id AND revoked_at_utc IS NULL;",
                cancellationToken, ("$id", id), ("$now", Timestamp(DateTimeOffset.UtcNow))).ConfigureAwait(false);
        if (changed == 1)
        {
            await WriteManagementAuditAsync(connection, transaction, delete ? "mcp.key.delete" : "mcp.key.revoke", id, actor, remoteIp,
                null, cancellationToken).ConfigureAwait(false);
        }
        var succeeded = changed == 1;
        if (!delete && !succeeded)
        {
            // 断线重试吊销时返回既有结果，避免产生重复管理审计。
            await using var revoked = Command(connection, transaction,
                "SELECT EXISTS (SELECT 1 FROM mcp_api_keys WHERE id = $id AND revoked_at_utc IS NOT NULL);", ("$id", id));
            succeeded = (long)(await revoked.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) ?? 0L) == 1;
        }
        transaction.Commit();
        if (changed == 1)
            adminStore.PublishAudit(delete ? "mcp.key.delete" : "mcp.key.revoke", id.ToString(CultureInfo.InvariantCulture), actor, remoteIp);
        return succeeded;
    }

    public async Task<string?> ReadKeySecretAsync(long id, string actor, string? remoteIp, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        using var transaction = connection.BeginTransaction(deferred: false);
        await using var command = Command(connection, transaction, """
            SELECT protected_secret FROM mcp_api_keys WHERE id = $id AND revoked_at_utc IS NULL
            AND (expires_at_utc IS NULL OR expires_at_utc > $now);
            """, ("$id", id), ("$now", Timestamp(DateTimeOffset.UtcNow)));
        var protectedSecret = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as byte[];
        if (protectedSecret is null)
        {
            return null;
        }

        string secret;
        try
        {
            secret = protector.Unprotect(id, protectedSecret);
        }
        catch (Exception exception) when (exception is CryptographicException or IOException or UnauthorizedAccessException)
        {
            throw new McpStoreException("MCP_KEY_PROTECTION_UNAVAILABLE", 503, "MCP 加密密钥材料不可用，无法复制该 Key。");
        }
        await WriteManagementAuditAsync(connection, transaction, "mcp.key.copy", id, actor, remoteIp, null,
            cancellationToken).ConfigureAwait(false);
        transaction.Commit();
        adminStore.PublishAudit("mcp.key.copy", id.ToString(CultureInfo.InvariantCulture), actor, remoteIp);
        return secret;
    }

    public async Task<McpApiKey?> AuthenticateAsync(string secret, CancellationToken cancellationToken = default)
    {
        if (secret.Length != 70 || !secret.StartsWith("ipban_", StringComparison.Ordinal))
        {
            return null;
        }
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = Command(connection, null, KeySelect + """
             WHERE k.secret_hash = $hash AND k.revoked_at_utc IS NULL AND (k.expires_at_utc IS NULL OR k.expires_at_utc > $now);
            """, ("$hash", UserPasswordHasher.HashToken(secret)), ("$now", Timestamp(DateTimeOffset.UtcNow)));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ? ReadKey(reader) : null;
    }

    public async Task<bool> CanInvokeAsync(long id, string scope, bool write, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = Command(connection, null, """
            SELECT EXISTS (
                SELECT 1 FROM mcp_api_keys k
                JOIN mcp_api_key_scopes s ON s.key_id = k.id
                JOIN mcp_settings cfg ON cfg.id = 1 AND cfg.enabled = 1
                WHERE k.id = $id AND k.revoked_at_utc IS NULL AND (k.expires_at_utc IS NULL OR k.expires_at_utc > $now)
                  AND s.scope = $scope AND ($write = 0 OR k.mode = 'write')
            );
            """, ("$id", id), ("$scope", scope), ("$write", write ? 1 : 0), ("$now", Timestamp(DateTimeOffset.UtcNow)));
        return (long)(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) ?? 0L) == 1;
    }

    public async Task<long> BeginCallAsync(McpCallStart call, CancellationToken cancellationToken = default)
    {
        var id = ids.NewId;
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, null, """
            INSERT INTO mcp_call_audits(id, occurred_at_utc, key_id, key_name, key_prefix, trace_id, remote_ip, path, method,
                tool, status, request_headers, request_body)
            VALUES ($id, $now, $key, $name, $prefix, $trace, $ip, $path, $method, $tool, 'pending', $headers, $body);
            """, cancellationToken, ("$id", id), ("$now", Timestamp(DateTimeOffset.UtcNow)), ("$key", call.Key?.Id),
            ("$name", call.Key?.Name), ("$prefix", call.Key?.Prefix), ("$trace", call.TraceId), ("$ip", call.RemoteIp),
            ("$path", call.Path), ("$method", call.Method), ("$tool", call.Tool), ("$headers", call.RequestHeaders),
            ("$body", call.RequestBody)).ConfigureAwait(false);
        return id;
    }

    public async Task CompleteCallAsync(long id, string status, int httpStatus, long durationMs, string? responseHeaders,
        string? responseBody, CancellationToken cancellationToken = default)
    {
        if (status is not ("success" or "denied" or "error" or "uncertain"))
        {
            throw new ArgumentOutOfRangeException(nameof(status));
        }
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var changed = await ExecuteAsync(connection, null, """
            UPDATE mcp_call_audits SET status = $status, http_status = $http, duration_ms = $duration,
                response_headers = $headers, response_body = $body WHERE id = $id AND status = 'pending';
            """, cancellationToken, ("$id", id), ("$status", status), ("$http", httpStatus), ("$duration", durationMs),
            ("$headers", responseHeaders), ("$body", responseBody)).ConfigureAwait(false);
        if (changed != 1)
        {
            throw new InvalidOperationException("MCP 审计结果无法写入待完成记录。");
        }
    }

    public async Task<McpCallPage> ListCallsAsync(McpCallFilter filter, CancellationToken cancellationToken = default)
    {
        if (filter.Page < 1 || filter.PageSize is < 1 or > 100 || filter.FromUtc > filter.ToUtc)
        {
            throw new McpStoreException("INVALID_MCP_AUDIT_FILTER", 400, "请提供有效的时间范围、页码和分页大小。");
        }
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        using var transaction = connection.BeginTransaction(deferred: true);
        (string Condition, string Name, object? Value)[] options =
        [
            ("occurred_at_utc >= $from", "$from", Timestamp(filter.FromUtc)),
            ("occurred_at_utc <= $to", "$to", Timestamp(filter.ToUtc)),
            ("key_id = $key", "$key", filter.KeyId), ("tool = $tool", "$tool", filter.Tool),
            ("status = $status", "$status", filter.Status)
        ];
        // 条件仅来自固定 SQL 片段，筛选值仍走绑定。省略空条件后 SQLite 可使用时间和 Key 索引。
        var selected = options.Where(option => option.Value is not null).ToArray();
        var filters = selected.Length == 0 ? string.Empty : " WHERE " + string.Join(" AND ", selected.Select(option => option.Condition));
        var parameters = selected.Select(option => (option.Name, option.Value)).ToArray();
        await using var count = Command(connection, transaction, "SELECT COUNT(*) FROM mcp_call_audits" + filters, parameters);
        var total = (long)(await count.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) ?? 0L);
        await using var command = Command(connection, transaction, "SELECT " + CallColumns + " FROM mcp_call_audits" + filters
            + " ORDER BY occurred_at_utc DESC, id DESC LIMIT $limit OFFSET $offset;", parameters);
        command.Parameters.AddWithValue("$limit", filter.PageSize);
        command.Parameters.AddWithValue("$offset", ((long)filter.Page - 1) * filter.PageSize);
        var items = new List<McpCallSummary>();
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                items.Add(ReadCall(reader));
            }
        }
        transaction.Commit();
        return new McpCallPage([.. items], total);
    }

    public async Task<McpCallDetail?> GetCallAsync(long id, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = Command(connection, null, "SELECT " + CallColumns + """
            , path, request_headers, request_body, response_headers, response_body FROM mcp_call_audits WHERE id = $id;
            """, ("$id", id));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
            ? new McpCallDetail(ReadCall(reader), reader.GetString(12), ReadText(reader, 13), ReadText(reader, 14), ReadText(reader, 15), ReadText(reader, 16))
            : null;
    }

    public async Task<int> PruneAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        using var transaction = connection.BeginTransaction(deferred: false);
        var settings = await ReadSettingsAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
        var cutoff = Timestamp(DateTimeOffset.UtcNow.AddDays(-settings.AuditRetentionDays));
        // 小批次持有写锁。未完成的调用仍需写回结果，不参与清理。
        var changed = await ExecuteAsync(connection, transaction, """
            DELETE FROM mcp_call_audits WHERE id IN (
                SELECT id FROM mcp_call_audits WHERE occurred_at_utc < $cutoff AND status <> 'pending'
                ORDER BY occurred_at_utc, id LIMIT 500
            );
            """, cancellationToken, ("$cutoff", cutoff)).ConfigureAwait(false);
        transaction.Commit();
        return changed;
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = adminStore.DatabasePath,
            Mode = SqliteOpenMode.ReadWrite,
            ForeignKeys = true,
            DefaultTimeout = 10
        }.ToString());
        try
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static async Task<McpSettings> ReadSettingsAsync(SqliteConnection connection, SqliteTransaction? transaction,
        CancellationToken cancellationToken)
    {
        await using var command = Command(connection, transaction, "SELECT enabled, audit_retention_days FROM mcp_settings WHERE id = 1;");
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            throw new McpStoreException("MCP_SETTINGS_UNAVAILABLE", 503, "MCP 设置尚未初始化。");
        }
        return new McpSettings(reader.GetBoolean(0), reader.GetInt32(1));
    }

    private static Task<int> WriteManagementAuditAsync(SqliteConnection connection, SqliteTransaction transaction, string action,
        long? target, string actor, string? remoteIp, string? detail, CancellationToken cancellationToken) =>
        ExecuteAsync(connection, transaction, """
            INSERT INTO audit_records(occurred_at_utc, action, category, actor_username, target, detail_json, remote_ip, success)
            VALUES ($now, $action, 'mcp', $actor, $target, $detail, $ip, 1);
            """, cancellationToken, ("$now", Timestamp(DateTimeOffset.UtcNow)), ("$action", action), ("$actor", actor),
            ("$target", target?.ToString(CultureInfo.InvariantCulture)), ("$detail", detail), ("$ip", remoteIp));

    private static async Task<int> ExecuteAsync(SqliteConnection connection, SqliteTransaction? transaction, string sql,
        CancellationToken cancellationToken, params (string Name, object? Value)[] parameters)
    {
        await using var command = Command(connection, transaction, sql, parameters);
        return await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static SqliteCommand Command(SqliteConnection connection, SqliteTransaction? transaction, string sql,
        params (string Name, object? Value)[] parameters)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach (var parameter in parameters)
        {
            command.Parameters.AddWithValue(parameter.Name, parameter.Value ?? DBNull.Value);
        }
        return command;
    }

    private static McpApiKey ReadKey(SqliteDataReader reader) => new(reader.GetInt64(0), reader.GetString(1), reader.GetString(2),
        reader.GetString(3), ReadTimestamp(reader, 4)!.Value, ReadTimestamp(reader, 5), ReadTimestamp(reader, 6),
        ReadText(reader, 7)?.Split(',') ?? []);

    private static McpCallSummary ReadCall(SqliteDataReader reader) => new(reader.GetInt64(0), ReadTimestamp(reader, 1)!.Value,
        reader.IsDBNull(2) ? null : reader.GetInt64(2), ReadText(reader, 3), ReadText(reader, 4), reader.GetString(5),
        ReadText(reader, 6), ReadText(reader, 7), ReadText(reader, 8), reader.GetString(9), reader.IsDBNull(10) ? null : reader.GetInt32(10),
        reader.IsDBNull(11) ? null : reader.GetInt64(11));

    private static string? ReadText(SqliteDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static DateTimeOffset? ReadTimestamp(SqliteDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null
        : DateTimeOffset.ParseExact(reader.GetString(ordinal), "O", CultureInfo.InvariantCulture);

    private static string? Timestamp(DateTimeOffset? value) => value?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
}
