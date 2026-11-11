using System.Data;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using IpBan.Api.Models;
using IpBan.Api.Options;
using IpBan.Shared.Models;
using IpBan.Shared.Logging.Syslog;
using IpBan.Shared.Service;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace IpBan.Api.Service.impl;

/// <summary>
/// 管理台只读/配置数据访问。业务 ID 由 SQLite 内部序列生成，登录事件仍由 Agent 统一写入。
/// </summary>
public sealed partial class SqliteAdminStore(
    IOptions<ManagementDataOptions> options,
    IHostEnvironment environment,
    SyslogRuntime? syslog = null)
{
    private readonly SyslogRuntime? _syslog = syslog;
    private readonly string _databasePath = ResolvePath(options.Value.DataDirectory, options.Value.DatabaseFileName, environment.ContentRootPath);
    private readonly string _backupDirectory = ResolveDirectory(options.Value.BackupDirectory, environment.ContentRootPath);
    private readonly string _logDirectory = ResolveDirectory(options.Value.LogDirectory, environment.ContentRootPath);

    public string DatabasePath => _databasePath;

    public async Task<OverviewContract> GetOverviewAsync(
        long activeConnections,
        long activeSessions,
        string firewallProvider,
        FirewallStatus firewallStatus,
        string? trendRange = null,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow;
        var normalizedRange = NormalizeTrendRange(trendRange);
        var sinceUtc = normalizedRange switch
        {
            "7d" => StartOfUtcDay(now).AddDays(-6),
            "1m" => StartOfUtcDay(now).AddDays(-29),
            _ => now.AddHours(-24)
        };
        var since = sinceUtc.ToString("O", CultureInfo.InvariantCulture);
        var success = await ScalarLongAsync(connection, "SELECT COUNT(*) FROM login_events WHERE occurred_at_utc >= $since AND is_success = 1;", cancellationToken, ("$since", since)).ConfigureAwait(false);
        var failure = await ScalarLongAsync(connection, "SELECT COUNT(*) FROM login_events WHERE occurred_at_utc >= $since AND is_success = 0;", cancellationToken, ("$since", since)).ConfigureAwait(false);
        var observeOnly = await ScalarLongAsync(connection, "SELECT COUNT(*) FROM login_events WHERE occurred_at_utc >= $since AND completeness_level = 'ObserveOnly';", cancellationToken, ("$since", since)).ConfigureAwait(false);
        var observeOnlyWithoutIp = await ScalarLongAsync(connection, """
            SELECT COUNT(*) FROM login_events
            WHERE occurred_at_utc >= $since AND completeness_level = 'ObserveOnly'
                AND (remote_ip IS NULL OR remote_ip = '');
            """, cancellationToken, ("$since", since)).ConfigureAwait(false);
        var activeBans = await ScalarLongAsync(connection, "SELECT COUNT(*) FROM firewall_actions a WHERE a.status='Applied' AND a.action IN ('ban','auto-ban') AND a.id=(SELECT id FROM firewall_actions e WHERE e.source_ip=a.source_ip AND ((e.action IN ('ban','auto-ban') AND e.status='Applied') OR (e.action IN ('unban','auto-unban','manual-unban') AND e.status='Removed')) ORDER BY id DESC LIMIT 1);", cancellationToken).ConfigureAwait(false);
        var lastLogin = await ScalarStringAsync(connection, "SELECT occurred_at_utc FROM login_events ORDER BY occurred_at_utc DESC LIMIT 1;", cancellationToken).ConfigureAwait(false);
        var lastAudit = await ScalarStringAsync(connection, "SELECT occurred_at_utc FROM audit_records ORDER BY occurred_at_utc DESC LIMIT 1;", cancellationToken).ConfigureAwait(false);
        var lastBackup = await ScalarStringAsync(connection, "SELECT created_at_utc FROM backup_records ORDER BY created_at_utc DESC LIMIT 1;", cancellationToken).ConfigureAwait(false);
        var lastRotation = await ScalarStringAsync(connection, "SELECT created_at_utc FROM log_rotation_records ORDER BY created_at_utc DESC LIMIT 1;", cancellationToken).ConfigureAwait(false);
        var size = File.Exists(_databasePath) ? new FileInfo(_databasePath).Length : 0;
        var logFiles = Directory.Exists(_logDirectory)
            ? Directory.EnumerateFiles(_logDirectory, "ipban-*.ndjson*").Select(path => new FileInfo(path)).ToArray()
            : [];
        var trend = await QueryTrendAsync(connection, now, normalizedRange, cancellationToken).ConfigureAwait(false);
        var topIps = await QueryTopIpsAsync(connection, since, cancellationToken).ConfigureAwait(false);
        var protocols = await QueryProtocolsAsync(connection, since, cancellationToken).ConfigureAwait(false);
        var recentEvents = await QueryRecentEventsAsync(connection, cancellationToken).ConfigureAwait(false);
        return new OverviewContract(
            now,
            normalizedRange,
            Ready: true,
            firewallProvider,
            firewallStatus,
            activeConnections,
            activeSessions,
            success,
            failure,
            observeOnly,
            activeBans,
            ExpiringBans: 0,
            trend.ToArray(),
            topIps.ToArray(),
            protocols.ToArray(),
            recentEvents.ToArray(),
            new OverviewStorageContract(
                size,
                logFiles.Where(file => !file.Name.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)).Sum(file => file.Length),
                logFiles.Where(file => file.Name.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)).Sum(file => file.Length),
                await ScalarStringAsync(connection, "SELECT MIN(occurred_at_utc) FROM login_events;", cancellationToken).ConfigureAwait(false) is { } oldest ? ParseUtc(oldest) : null,
                logFiles.Length == 0 ? null : logFiles.Max(file => new DateTimeOffset(file.LastWriteTimeUtc, TimeSpan.Zero)),
                ParseNullableUtc(lastRotation),
                ParseNullableUtc(lastBackup)),
            ParseNullableUtc(lastLogin),
            ParseNullableUtc(lastAudit))
        {
            ObserveOnlyWithoutIp = observeOnlyWithoutIp
        };
    }

    private static async Task<IReadOnlyList<OverviewTrendPoint>> QueryTrendAsync(SqliteConnection connection, DateTimeOffset now, string range, CancellationToken cancellationToken)
    {
        var values = new Dictionary<string, (long Success, long Failure, long ObserveOnly)>(StringComparer.Ordinal);
        var isHourly = range == "24h";
        var since = isHourly ? now.AddHours(-24) : StartOfUtcDay(now).AddDays(range == "7d" ? -6 : -29);
        await using var command = connection.CreateCommand();
        var bucketExpression = isHourly ? "substr(occurred_at_utc, 1, 13)" : "substr(occurred_at_utc, 1, 10)";
        command.CommandText = $"SELECT {bucketExpression}, SUM(CASE WHEN is_success = 1 THEN 1 ELSE 0 END), SUM(CASE WHEN is_success = 0 THEN 1 ELSE 0 END), SUM(CASE WHEN completeness_level = 'ObserveOnly' THEN 1 ELSE 0 END) FROM login_events WHERE occurred_at_utc >= $since GROUP BY {bucketExpression};";
        command.Parameters.AddWithValue("$since", since.ToString("O", CultureInfo.InvariantCulture));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            values[reader.GetString(0)] = (reader.GetInt64(1), reader.GetInt64(2), reader.GetInt64(3));
        }

        var pointCount = isHourly ? 24 : range == "7d" ? 7 : 30;
        var points = new List<OverviewTrendPoint>(pointCount);
        var start = isHourly
            ? new DateTimeOffset(now.Year, now.Month, now.Day, now.Hour, 0, 0, TimeSpan.Zero).AddHours(-23)
            : StartOfUtcDay(now).AddDays(-(pointCount - 1));
        for (var index = 0; index < pointCount; index++)
        {
            var point = isHourly ? start.AddHours(index) : start.AddDays(index);
            var key = isHourly
                ? point.ToString("yyyy-MM-ddTHH", CultureInfo.InvariantCulture)
                : point.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            values.TryGetValue(key, out var value);
            points.Add(new OverviewTrendPoint(
                point.ToString(isHourly ? "MM-dd HH:mm" : "MM-dd", CultureInfo.InvariantCulture),
                point,
                value.Success,
                value.Failure,
                value.ObserveOnly));
        }

        return points;
    }

    private static async Task<IReadOnlyList<OverviewTopSourceIp>> QueryTopIpsAsync(SqliteConnection connection, string since, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        // 观察事件优先单独归类，保证每个来源的三段柱形合计等于事件总数。
        command.CommandText = """
            SELECT remote_ip, COUNT(*),
                   COUNT(CASE WHEN completeness_level <> 'ObserveOnly' AND is_success = 1 THEN 1 END),
                   COUNT(CASE WHEN completeness_level <> 'ObserveOnly' AND is_success = 0 THEN 1 END),
                   COUNT(CASE WHEN completeness_level = 'ObserveOnly' THEN 1 END)
            FROM login_events
            WHERE occurred_at_utc >= $since AND remote_ip IS NOT NULL AND remote_ip <> ''
            GROUP BY remote_ip
            ORDER BY COUNT(*) DESC, remote_ip
            LIMIT 10;
            """;
        command.Parameters.AddWithValue("$since", since);
        var result = new List<OverviewTopSourceIp>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            result.Add(new OverviewTopSourceIp(
                reader.GetString(0), reader.GetInt64(1), reader.GetInt64(2), reader.GetInt64(3), reader.GetInt64(4)));
        }
        return result;
    }

    private static async Task<IReadOnlyList<OverviewProtocolCount>> QueryProtocolsAsync(SqliteConnection connection, string since, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT protocol, COUNT(*), evidence_source, local_process_name
            FROM login_events WHERE occurred_at_utc >= $since
            GROUP BY protocol, evidence_source, local_process_name;
            """;
        command.Parameters.AddWithValue("$since", since);
        var counts = new Dictionary<string, long>(StringComparer.Ordinal);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            var protocol = LoginEventProtocol.ResolveStored(reader.GetString(0),
                reader.IsDBNull(2) ? null : reader.GetString(2), reader.IsDBNull(3) ? null : reader.GetString(3));
            counts[protocol] = counts.GetValueOrDefault(protocol) + reader.GetInt64(1);
        }
        return counts.OrderByDescending(item => item.Value)
            .Select(item => new OverviewProtocolCount(item.Key, item.Value)).ToArray();
    }

    private static async Task<IReadOnlyList<OverviewRecentEvent>> QueryRecentEventsAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT occurred_at_utc, protocol, is_success, remote_ip, username, remote_port, local_ip, local_port, local_process_name, completeness_level, collector, evidence_source FROM login_events ORDER BY occurred_at_utc DESC, id DESC LIMIT 20;";
        var result = new List<OverviewRecentEvent>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            var processName = reader.IsDBNull(8) ? null : reader.GetString(8);
            var evidenceSource = reader.IsDBNull(11) ? null : reader.GetString(11);
            result.Add(new OverviewRecentEvent(
                ParseUtc(reader.GetString(0)), LoginEventProtocol.ResolveStored(reader.GetString(1), evidenceSource, processName), reader.GetInt64(2) != 0,
                reader.IsDBNull(3) ? null : reader.GetString(3), reader.IsDBNull(4) ? null : reader.GetString(4),
                reader.IsDBNull(5) ? null : reader.GetInt32(5), reader.IsDBNull(6) ? null : reader.GetString(6),
                reader.IsDBNull(7) ? null : reader.GetInt32(7), processName,
                reader.GetString(9), reader.GetString(10), evidenceSource));
        }
        return result;
    }

    public async Task<IReadOnlyList<UserSummaryContract>> ListUsersAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT id, username, display_name, enabled, created_at_utc, last_login_at_utc FROM users ORDER BY username;";
        var result = new List<UserSummaryContract>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            result.Add(new UserSummaryContract(
                reader.GetInt64(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetInt64(3) != 0,
                ParseUtc(reader.GetString(4)),
                reader.IsDBNull(5) ? null : ParseUtc(reader.GetString(5))));
        }

        return result;
    }

    public Task<UserSummaryContract> UpsertUserAsync(long? id, UpsertUserRequest request, CancellationToken cancellationToken = default) =>
        UpsertUserAsync(id, request, null, "user.upsert", cancellationToken);

    internal async Task<UserSummaryContract> UpsertUserAsync(long? id, UpsertUserRequest request, ManagementAuditContext? audit,
        string auditAction, CancellationToken cancellationToken)
    {
        var username = request.Username.Trim();
        var displayName = request.DisplayName.Trim();
        if (username.Length is < 1 or > 128 || displayName.Length is < 1 or > 256)
        {
            throw new ArgumentException("用户名和显示名称长度无效。");
        }

        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture);
        await using var transaction = connection.BeginTransaction();
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        if (id is { } existingId)
        {
            command.CommandText = string.IsNullOrWhiteSpace(request.Password)
                ? "UPDATE users SET username=$username, display_name=$displayName, enabled=$enabled, updated_at_utc=$updated WHERE id=$id;"
                : "UPDATE users SET username=$username, display_name=$displayName, password_hash=$passwordHash, enabled=$enabled, updated_at_utc=$updated WHERE id=$id;";
            command.Parameters.AddWithValue("$id", existingId);
        }
        else
        {
            if (string.IsNullOrWhiteSpace(request.Password))
            {
                throw new ArgumentException("新用户必须设置密码。");
            }

            command.CommandText = "INSERT INTO users(username, password_hash, display_name, enabled, created_at_utc, updated_at_utc) VALUES ($username, $passwordHash, $displayName, $enabled, $created, $updated);";
            command.Parameters.AddWithValue("$created", now);
        }

        command.Parameters.AddWithValue("$username", username);
        command.Parameters.AddWithValue("$displayName", displayName);
        command.Parameters.AddWithValue("$enabled", request.Enabled ? 1 : 0);
        command.Parameters.AddWithValue("$updated", now);
        if (!string.IsNullOrWhiteSpace(request.Password))
        {
            command.Parameters.AddWithValue("$passwordHash", UserPasswordHasher.Hash(request.Password));
        }

        var affected = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        if (id is not null && affected == 0)
        {
            throw new KeyNotFoundException("用户不存在。");
        }

        await CommitAuditAsync(connection, transaction, audit, auditAction, "user", username, cancellationToken).ConfigureAwait(false);
        var users = await ListUsersAsync(cancellationToken).ConfigureAwait(false);
        return id is { } updatedId
            ? users.First(user => user.Id == updatedId)
            : users.First(user => user.Username.Equals(username, StringComparison.Ordinal));
    }

    public async Task<bool> HasUsersAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT EXISTS(SELECT 1 FROM users LIMIT 1);";
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture) != 0;
    }

    public async Task<UserSummaryContract?> AuthenticateUserAsync(
        string username,
        string password,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT id, username, password_hash, display_name, enabled, created_at_utc, last_login_at_utc FROM users WHERE username=$username LIMIT 1;";
        command.Parameters.AddWithValue("$username", username.Trim());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
            || reader.GetInt64(4) == 0
            || !UserPasswordHasher.Verify(password, reader.GetString(2)))
        {
            return null;
        }

        var user = new UserSummaryContract(
            reader.GetInt64(0), reader.GetString(1), reader.GetString(3), true,
            ParseUtc(reader.GetString(5)), DateTimeOffset.UtcNow);
        await reader.DisposeAsync().ConfigureAwait(false);
        await using var update = connection.CreateCommand();
        update.CommandText = "UPDATE users SET last_login_at_utc=$lastLogin, updated_at_utc=$updated WHERE id=$id;";
        update.Parameters.AddWithValue("$lastLogin", user.LastLoginAtUtc!.Value.ToString("O", CultureInfo.InvariantCulture));
        update.Parameters.AddWithValue("$updated", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
        update.Parameters.AddWithValue("$id", user.Id);
        await update.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        return user;
    }

    public Task CreateUserSessionAsync(long userId, string tokenHash, string? remoteIp, DateTimeOffset expiresAtUtc,
        CancellationToken cancellationToken = default) =>
        CreateUserSessionAsync(userId, tokenHash, remoteIp, expiresAtUtc, null, null, null, cancellationToken);

    internal async Task CreateUserSessionAsync(long userId, string tokenHash, string? remoteIp, DateTimeOffset expiresAtUtc,
        string? auditAction, string? actor, string? traceId, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction();
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO user_sessions(id, user_id, token_hash, remote_ip, created_at_utc, last_seen_at_utc, expires_at_utc, revoked) VALUES ($id, $userId, $tokenHash, $remoteIp, $created, $lastSeen, $expires, 0);";
        var sessionId = BitConverter.ToInt64(RandomNumberGenerator.GetBytes(sizeof(long))) & long.MaxValue;
        command.Parameters.AddWithValue("$id", sessionId == 0 ? 1 : sessionId);
        command.Parameters.AddWithValue("$userId", userId);
        command.Parameters.AddWithValue("$tokenHash", tokenHash);
        command.Parameters.AddWithValue("$remoteIp", (object?)remoteIp ?? DBNull.Value);
        command.Parameters.AddWithValue("$created", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$lastSeen", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$expires", expiresAtUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        var sourceId = userId.ToString(CultureInfo.InvariantCulture);
        if (auditAction is not null)
            await AppendAuditCoreAsync(connection, transaction, auditAction, "login", sourceId, null, remoteIp, true, actor,
                cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        if (auditAction is not null) PublishAudit(auditAction, sourceId, actor, remoteIp, traceId: traceId);
    }

    public async Task<UserSummaryContract?> GetUserBySessionAsync(string tokenHash, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT u.id, u.username, u.display_name, u.enabled, u.created_at_utc, u.last_login_at_utc FROM user_sessions s INNER JOIN users u ON u.id=s.user_id WHERE s.token_hash=$tokenHash AND s.revoked=0 AND s.expires_at_utc > $now AND u.enabled=1 LIMIT 1;";
        command.Parameters.AddWithValue("$tokenHash", tokenHash);
        command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
            ? new UserSummaryContract(reader.GetInt64(0), reader.GetString(1), reader.GetString(2), reader.GetInt64(3) != 0, ParseUtc(reader.GetString(4)), reader.IsDBNull(5) ? null : ParseUtc(reader.GetString(5)))
            : null;
    }

    public Task RevokeUserSessionAsync(string tokenHash, CancellationToken cancellationToken = default) =>
        RevokeUserSessionAsync(tokenHash, null, null, null, cancellationToken);

    internal async Task RevokeUserSessionAsync(string tokenHash, string? actor, string? remoteIp, string? traceId,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction();
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "UPDATE user_sessions SET revoked=1, last_seen_at_utc=$now WHERE token_hash=$tokenHash AND revoked=0;";
        command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$tokenHash", tokenHash);
        var audit = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) > 0 && actor is not null;
        if (audit)
            await AppendAuditCoreAsync(connection, transaction, "login.logout", "login", null, null, remoteIp, true, actor,
                cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        if (audit) PublishAudit("login.logout", null, actor, remoteIp, traceId: traceId);
    }

    public async Task<IReadOnlyList<SystemSettingContract>> ListSettingsAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT setting_key, setting_value, is_secret, updated_at_utc, updated_by FROM system_settings ORDER BY setting_key;";
        var result = new List<SystemSettingContract>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            result.Add(new SystemSettingContract(
                reader.GetString(0),
                reader.GetInt64(2) != 0 ? null : (reader.IsDBNull(1) ? null : reader.GetString(1)),
                reader.GetInt64(2) != 0,
                ParseUtc(reader.GetString(3)),
                reader.IsDBNull(4) ? null : reader.GetString(4)));
        }

        return result;
    }

    public async Task<IReadOnlyList<AuditRecordContract>> ListAuditAsync(int limit = 100, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT id, occurred_at_utc, action, category, actor_username, target, detail_json, remote_ip, success FROM audit_records ORDER BY occurred_at_utc DESC, id DESC LIMIT $limit;";
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 1000));
        var result = new List<AuditRecordContract>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            result.Add(new AuditRecordContract(
                reader.GetInt64(0), ParseUtc(reader.GetString(1)), reader.GetString(2), reader.GetString(3),
                reader.IsDBNull(4) ? null : reader.GetString(4), reader.IsDBNull(5) ? null : reader.GetString(5),
                reader.IsDBNull(6) ? null : reader.GetString(6), reader.IsDBNull(7) ? null : reader.GetString(7),
                reader.GetInt64(8) != 0));
        }

        return result;
    }

    public async Task<IReadOnlyList<BackupRecordContract>> ListBackupsAsync(int limit = 100, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT id, backup_kind, backup_path, size_bytes, sha256, created_at_utc, status, error_message FROM backup_records ORDER BY created_at_utc DESC, id DESC LIMIT $limit;";
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 1000));
        var result = new List<BackupRecordContract>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            result.Add(new BackupRecordContract(
                reader.GetInt64(0), reader.GetString(1), reader.GetString(2), reader.GetInt64(3),
                reader.IsDBNull(4) ? null : reader.GetString(4), ParseUtc(reader.GetString(5)), reader.GetString(6),
                reader.IsDBNull(7) ? null : reader.GetString(7)));
        }

        return result;
    }

    public async Task<long> GetLatestFirewallActionIdAsync(CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        return await ScalarLongAsync(connection, "SELECT COALESCE(MAX(id),0) FROM firewall_actions;", cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<FirewallActionContract>> ListFirewallActionsAsync(
        string? status = null,
        int limit = 200,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        // 历史 status 表示当时执行结果，当前代次另算，不能因手动解封篡改历史 Applied。
        command.CommandText = "SELECT a.id, a.created_at_utc, a.source_ip, a.action, a.status, a.provider, a.error_code, a.error_message, a.completed_at_utc, current.id, current.status FROM firewall_actions a LEFT JOIN firewall_actions current ON current.id=(SELECT e.id FROM firewall_actions e WHERE e.source_ip=a.source_ip AND ((e.action IN ('ban','auto-ban') AND e.status='Applied') OR (e.action IN ('unban','auto-unban','manual-unban') AND e.status='Removed')) ORDER BY e.id DESC LIMIT 1) WHERE ($status IS NULL OR a.status=$status) ORDER BY a.created_at_utc DESC, a.id DESC LIMIT $limit;";
        command.Parameters.AddWithValue("$status", (object?)status ?? DBNull.Value);
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 1000));
        var result = new List<FirewallActionContract>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            var successfulBan = reader.GetString(4) == "Applied" && reader.GetString(3) is "ban" or "auto-ban";
            var canUnban = successfulBan && !reader.IsDBNull(9) && reader.GetInt64(0) == reader.GetInt64(9);
            var currentStatus = successfulBan && !canUnban
                ? !reader.IsDBNull(10) && reader.GetString(10) == "Removed" ? "Removed" : "Superseded"
                : reader.GetString(4);
            result.Add(new FirewallActionContract(
                reader.GetInt64(0), ParseUtc(reader.GetString(1)), reader.GetString(2), reader.GetString(3), reader.GetString(4), reader.GetString(5),
                reader.IsDBNull(6) ? null : reader.GetString(6), reader.IsDBNull(7) ? null : reader.GetString(7), reader.IsDBNull(8) ? null : ParseUtc(reader.GetString(8)),
                canUnban, currentStatus));
        }

        return result;
    }

    public async Task<IReadOnlyList<CertificateMetadataContract>> ListCertificatesAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT id, certificate_path, subject, issuer, thumbprint, not_before_utc, not_after_utc, uploaded_at_utc, active FROM certificate_metadata ORDER BY uploaded_at_utc DESC;";
        var result = new List<CertificateMetadataContract>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            result.Add(new CertificateMetadataContract(
                reader.GetInt64(0), reader.GetString(1), reader.GetString(2), reader.IsDBNull(3) ? null : reader.GetString(3),
                reader.GetString(4), ParseUtc(reader.GetString(5)), ParseUtc(reader.GetString(6)), ParseUtc(reader.GetString(7)), reader.GetInt64(8) != 0));
        }

        if (result.Count == 0)
        {
            var activePath = Path.Combine(
                Path.GetDirectoryName(_databasePath) ?? throw new InvalidOperationException("无法解析数据目录。"),
                "certificates",
                CertificateRuntime.ActiveFileName);
            if (File.Exists(activePath))
            {
                using var certificate = CertificateRuntime.Load(activePath);
                result.Add(new CertificateMetadataContract(
                    0,
                    activePath,
                    certificate.Subject,
                    certificate.Issuer,
                    certificate.Thumbprint ?? string.Empty,
                    certificate.NotBefore.ToUniversalTime(),
                    certificate.NotAfter.ToUniversalTime(),
                    new DateTimeOffset(File.GetCreationTimeUtc(activePath), TimeSpan.Zero),
                    true));
            }
        }

        return result;
    }

    private const string AccessListColumns = "id, address, entry_type, source, reason, priority, status, created_by, created_at_utc, effective_at_utc, expires_at_utc, released_at_utc";

    public Task<IReadOnlyList<AccessListEntryContract>> ListAccessListAsync(CancellationToken cancellationToken = default) =>
        ListAccessListPageAsync(-1, 0, cancellationToken);

    internal async Task<IReadOnlyList<AccessListEntryContract>> ListAccessListPageAsync(int limit, int offset, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT {AccessListColumns} FROM access_list_entries ORDER BY priority, created_at_utc DESC, id DESC LIMIT $limit OFFSET $offset;";
        command.Parameters.AddWithValue("$limit", limit);
        command.Parameters.AddWithValue("$offset", offset);
        var result = new List<AccessListEntryContract>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            result.Add(ReadAccessListEntry(reader));
        }

        return result;
    }

    private static AccessListEntryContract ReadAccessListEntry(SqliteDataReader reader) => new(
        reader.GetInt64(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
        reader.IsDBNull(4) ? null : reader.GetString(4), reader.GetInt32(5), reader.GetString(6),
        reader.IsDBNull(7) ? null : reader.GetString(7), ParseUtc(reader.GetString(8)),
        reader.IsDBNull(9) ? null : ParseUtc(reader.GetString(9)),
        reader.IsDBNull(10) ? null : ParseUtc(reader.GetString(10)),
        reader.IsDBNull(11) ? null : ParseUtc(reader.GetString(11)));

    public Task<AccessListEntryContract> UpsertAccessListAsync(long? id, UpsertAccessListEntryRequest request,
        CancellationToken cancellationToken = default) => UpsertAccessListAsync(id, request, null, cancellationToken);

    internal Task<AccessListEntryContract> UpsertAccessListAsync(long? id, UpsertAccessListEntryRequest request,
        ManagementAuditContext? audit, CancellationToken cancellationToken) =>
        UpsertAccessListCoreAsync(id, request, audit, "access-list.upsert", cancellationToken);

    internal Task<AccessListEntryContract> UpsertAccessListForMcpAsync(long? id, UpsertAccessListEntryRequest request,
        string actor, CancellationToken cancellationToken) => UpsertAccessListCoreAsync(id, request,
        new ManagementAuditContext(actor, null, null), "mcp.access-list.upsert", cancellationToken);

    private async Task<AccessListEntryContract> UpsertAccessListCoreAsync(long? id, UpsertAccessListEntryRequest request,
        ManagementAuditContext? audit, string auditAction, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction();
        var now = DateTimeOffset.UtcNow;
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        if (id is { } existingId)
        {
            command.CommandText = $"UPDATE access_list_entries SET address=$address, entry_type=$type, source=$source, reason=$reason, priority=$priority, status=$status, effective_at_utc=$effective, expires_at_utc=$expires WHERE id=$id RETURNING {AccessListColumns};";
            command.Parameters.AddWithValue("$id", existingId);
        }
        else
        {
            command.CommandText = $"INSERT INTO access_list_entries(address, entry_type, source, reason, priority, status, created_by, created_at_utc, effective_at_utc, expires_at_utc) VALUES ($address, $type, $source, $reason, $priority, $status, $createdBy, $created, $effective, $expires) RETURNING {AccessListColumns};";
            command.Parameters.AddWithValue("$createdBy", (object?)(audit?.Actor ?? request.CreatedBy) ?? DBNull.Value);
            command.Parameters.AddWithValue("$created", now.ToString("O", CultureInfo.InvariantCulture));
        }

        command.Parameters.AddWithValue("$address", request.Address.Trim());
        command.Parameters.AddWithValue("$type", request.EntryType.Trim());
        command.Parameters.AddWithValue("$source", request.Source.Trim());
        command.Parameters.AddWithValue("$reason", (object?)request.Reason ?? DBNull.Value);
        command.Parameters.AddWithValue("$priority", request.Priority);
        command.Parameters.AddWithValue("$status", request.Status.Trim());
        command.Parameters.AddWithValue("$effective", request.EffectiveAtUtc?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture) ?? (object)DBNull.Value);
        command.Parameters.AddWithValue("$expires", request.ExpiresAtUtc?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture) ?? (object)DBNull.Value);
        AccessListEntryContract entry;
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                throw new DBConcurrencyException("名单条目不存在。");
            entry = ReadAccessListEntry(reader);
        }
        await CommitAuditAsync(connection, transaction, audit, auditAction, "access-list", entry.Id.ToString(CultureInfo.InvariantCulture),
            cancellationToken).ConfigureAwait(false);
        return entry;
    }

    public Task<bool> DeleteAccessListAsync(long id, CancellationToken cancellationToken = default) =>
        DeleteAccessListAsync(id, null, cancellationToken);

    internal async Task<bool> DeleteAccessListAsync(long id, ManagementAuditContext? audit, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction();
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "DELETE FROM access_list_entries WHERE id=$id;";
        command.Parameters.AddWithValue("$id", id);
        if (await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) == 0) return false;
        await CommitAuditAsync(connection, transaction, audit, "access-list.delete", "access-list", id.ToString(CultureInfo.InvariantCulture),
            cancellationToken).ConfigureAwait(false);
        return true;
    }

    private const string PolicyColumns = "id, name, enabled, threshold, window_seconds, observe_seconds, cooldown_seconds, ban_duration_seconds, action, protocol, description, version, created_at_utc, updated_at_utc";

    public Task<IReadOnlyList<BanPolicyContract>> ListPoliciesAsync(CancellationToken cancellationToken = default) =>
        ListPolicyPageAsync(-1, 0, cancellationToken);

    internal async Task<IReadOnlyList<BanPolicyContract>> ListPolicyPageAsync(int limit, int offset, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT {PolicyColumns} FROM ban_policies ORDER BY name, id LIMIT $limit OFFSET $offset;";
        command.Parameters.AddWithValue("$limit", limit);
        command.Parameters.AddWithValue("$offset", offset);
        var result = new List<BanPolicyContract>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            result.Add(ReadPolicy(reader));
        }

        return result;
    }

    internal async Task<BanPolicyContract?> FindPolicyAsync(long id, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT {PolicyColumns} FROM ban_policies WHERE id=$id;";
        command.Parameters.AddWithValue("$id", id);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ? ReadPolicy(reader) : null;
    }

    private static BanPolicyContract ReadPolicy(SqliteDataReader reader)
    {
        // 旧版 Ban + 0 表示永久封禁，新写入的 0 统一使用 Observe。
        var durationSeconds = reader.GetInt32(7);
        var action = reader.GetString(8);
        if (durationSeconds == 0 && string.Equals(action, "Ban", StringComparison.OrdinalIgnoreCase))
            durationSeconds = -1;
        return new BanPolicyContract(
            reader.GetInt64(0), reader.GetString(1), reader.GetInt64(2) != 0, reader.GetInt32(3), reader.GetInt32(4),
            reader.GetInt32(5), reader.GetInt32(6), durationSeconds, action,
            reader.IsDBNull(9) ? null : reader.GetString(9), reader.IsDBNull(10) ? null : reader.GetString(10),
            reader.GetInt32(11), ParseUtc(reader.GetString(12)), ParseUtc(reader.GetString(13)));
    }

    public Task<BanPolicyContract> UpsertPolicyAsync(long? id, UpsertBanPolicyRequest request,
        CancellationToken cancellationToken = default) => UpsertPolicyAsync(id, request, null, cancellationToken);

    internal Task<BanPolicyContract> UpsertPolicyAsync(long? id, UpsertBanPolicyRequest request,
        ManagementAuditContext? audit, CancellationToken cancellationToken) =>
        UpsertPolicyCoreAsync(id, null, request, audit, "policy.upsert", cancellationToken);

    internal Task<BanPolicyContract> UpdatePolicyForMcpAsync(long id, int version, UpsertBanPolicyRequest request,
        string actor, CancellationToken cancellationToken) => UpsertPolicyCoreAsync(id, version, request,
        new ManagementAuditContext(actor, null, null), "mcp.policy.upsert", cancellationToken);

    private async Task<BanPolicyContract> UpsertPolicyCoreAsync(long? id, int? version, UpsertBanPolicyRequest request,
        ManagementAuditContext? audit, string auditAction, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction();
        var now = DateTimeOffset.UtcNow;
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        if (id is { } existingId)
        {
            command.CommandText = $"UPDATE ban_policies SET name=$name, enabled=$enabled, threshold=$threshold, window_seconds=$window, observe_seconds=$observe, cooldown_seconds=$cooldown, ban_duration_seconds=$duration, action=$action, protocol=$protocol, description=$description, version=version+1, updated_at_utc=$updated WHERE id=$id AND ($version IS NULL OR version=$version) RETURNING {PolicyColumns};";
            command.Parameters.AddWithValue("$id", existingId);
            command.Parameters.AddWithValue("$version", (object?)version ?? DBNull.Value);
        }
        else
        {
            command.CommandText = $"INSERT INTO ban_policies(name, enabled, threshold, window_seconds, observe_seconds, cooldown_seconds, ban_duration_seconds, action, protocol, description, version, created_at_utc, updated_at_utc) VALUES ($name, $enabled, $threshold, $window, $observe, $cooldown, $duration, $action, $protocol, $description, 1, $created, $updated) RETURNING {PolicyColumns};";
            command.Parameters.AddWithValue("$created", now.ToString("O", CultureInfo.InvariantCulture));
        }

        command.Parameters.AddWithValue("$name", request.Name.Trim());
        command.Parameters.AddWithValue("$enabled", request.Enabled ? 1 : 0);
        command.Parameters.AddWithValue("$threshold", request.Threshold);
        command.Parameters.AddWithValue("$window", request.WindowSeconds);
        command.Parameters.AddWithValue("$observe", request.ObserveSeconds);
        command.Parameters.AddWithValue("$cooldown", request.CooldownSeconds);
        command.Parameters.AddWithValue("$duration", request.BanDurationSeconds);
        // 0 只记录事件。用现有 Observe 动作区分旧版保存的永久封禁，无需改表。
        command.Parameters.AddWithValue("$action", request.BanDurationSeconds == 0 ? "Observe" : request.Action.Trim());
        command.Parameters.AddWithValue("$protocol", (object?)request.Protocol ?? DBNull.Value);
        command.Parameters.AddWithValue("$description", (object?)request.Description ?? DBNull.Value);
        command.Parameters.AddWithValue("$updated", now.ToString("O", CultureInfo.InvariantCulture));
        BanPolicyContract policy;
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                throw new DBConcurrencyException("策略已变更或不存在。");
            policy = ReadPolicy(reader);
        }
        await CommitAuditAsync(connection, transaction, audit, auditAction, "policy", policy.Id.ToString(CultureInfo.InvariantCulture),
            cancellationToken).ConfigureAwait(false);
        return policy;
    }

    public Task<bool> DeletePolicyAsync(long id, CancellationToken cancellationToken = default) =>
        DeletePolicyAsync(id, null, cancellationToken);

    internal async Task<bool> DeletePolicyAsync(long id, ManagementAuditContext? audit, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction();
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "DELETE FROM ban_policies WHERE id=$id;";
        command.Parameters.AddWithValue("$id", id);
        if (await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) == 0) return false;
        await CommitAuditAsync(connection, transaction, audit, "policy.delete", "policy", id.ToString(CultureInfo.InvariantCulture),
            cancellationToken).ConfigureAwait(false);
        return true;
    }

    public Task UpsertSettingAsync(string key, string? value, bool isSecret, string? updatedBy, CancellationToken cancellationToken = default) =>
        UpsertSettingAsync(key, value, isSecret, updatedBy, null, cancellationToken);

    internal async Task UpsertSettingAsync(string key, string? value, bool isSecret, string? updatedBy, ManagementAuditContext? audit,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction();
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO system_settings(setting_key, setting_value, is_secret, updated_at_utc, updated_by) VALUES ($key, $value, $secret, $updated, $by) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value, is_secret=excluded.is_secret, updated_at_utc=excluded.updated_at_utc, updated_by=excluded.updated_by;";
        command.Parameters.AddWithValue("$key", key);
        command.Parameters.AddWithValue("$value", (object?)value ?? DBNull.Value);
        command.Parameters.AddWithValue("$secret", isSecret ? 1 : 0);
        command.Parameters.AddWithValue("$updated", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$by", (object?)updatedBy ?? DBNull.Value);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        await CommitAuditAsync(connection, transaction, audit, "settings.update", "settings", key, cancellationToken).ConfigureAwait(false);
    }

    public async Task<CertificateMetadataContract> RegisterCertificateAsync(
        string certificatePath,
        System.Security.Cryptography.X509Certificates.X509Certificate2 certificate,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.Transaction = (Microsoft.Data.Sqlite.SqliteTransaction)transaction;
        var uploaded = DateTimeOffset.UtcNow;
        command.CommandText = "UPDATE certificate_metadata SET active=0; INSERT INTO certificate_metadata(certificate_path, subject, issuer, thumbprint, not_before_utc, not_after_utc, uploaded_at_utc, active) VALUES ($path, $subject, $issuer, $thumbprint, $notBefore, $notAfter, $uploaded, 1);";
        command.Parameters.AddWithValue("$path", certificatePath);
        command.Parameters.AddWithValue("$subject", certificate.Subject);
        command.Parameters.AddWithValue("$issuer", certificate.Issuer);
        command.Parameters.AddWithValue("$thumbprint", certificate.Thumbprint ?? string.Empty);
        command.Parameters.AddWithValue("$notBefore", certificate.NotBefore.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$notAfter", certificate.NotAfter.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$uploaded", uploaded.ToString("O", CultureInfo.InvariantCulture));
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return new CertificateMetadataContract(0, certificatePath, certificate.Subject, certificate.Issuer, certificate.Thumbprint ?? string.Empty, certificate.NotBefore.ToUniversalTime(), certificate.NotAfter.ToUniversalTime(), uploaded, true);
    }

    public async Task<CertificateMetadataContract> UploadPfxAsync(Stream input, CancellationToken cancellationToken = default)
    {
        var directory = Path.Combine(Path.GetDirectoryName(_databasePath) ?? throw new InvalidOperationException("无法解析数据目录。"), "certificates");
        Directory.CreateDirectory(directory);
        var temporaryPath = Path.Combine(directory, $"https-upload-{Guid.NewGuid():N}.pfx");
        var path = Path.Combine(directory, CertificateRuntime.ActiveFileName);
        await using (var output = File.Create(temporaryPath))
        {
            await input.CopyToAsync(output, cancellationToken).ConfigureAwait(false);
        }

        try
        {
            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            {
                File.SetUnixFileMode(temporaryPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
        catch (PlatformNotSupportedException)
        {
            // Windows 使用安装目录 ACL 控制证书文件访问。
        }

        var bytes = await File.ReadAllBytesAsync(temporaryPath, cancellationToken).ConfigureAwait(false);
        using var certificate = X509CertificateLoader.LoadPkcs12(bytes, string.Empty, X509KeyStorageFlags.EphemeralKeySet);
        File.Move(temporaryPath, path, true);
        return await RegisterCertificateAsync(path, certificate, cancellationToken).ConfigureAwait(false);
    }

    public async Task<BackupRecordContract> CreateBackupAsync(CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(_backupDirectory);
        var created = DateTimeOffset.UtcNow;
        var path = Path.Combine(_backupDirectory, $"ipban-{created:yyyyMMddHHmmssfff}.sqlite3");
        File.Copy(_databasePath, path, overwrite: false);
        await using var stream = File.OpenRead(path);
        var hash = Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false));
        var size = new FileInfo(path).Length;
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "INSERT INTO backup_records(backup_kind, backup_path, size_bytes, sha256, created_at_utc, status) VALUES ('sqlite', $path, $size, $sha256, $created, 'Completed');";
        command.Parameters.AddWithValue("$path", path);
        command.Parameters.AddWithValue("$size", size);
        command.Parameters.AddWithValue("$sha256", hash);
        command.Parameters.AddWithValue("$created", created.ToString("O", CultureInfo.InvariantCulture));
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        return new BackupRecordContract(0, "sqlite", path, size, hash, created, "Completed", null);
    }

    public Task AppendAuditAsync(
        string action,
        string category,
        string? target,
        string? detailJson,
        string? remoteIp,
        bool success,
        CancellationToken cancellationToken = default) =>
        AppendAuditAsync(action, category, target, detailJson, remoteIp, success, "local-admin", cancellationToken);

    public Task AppendAuditAsync(string action, string category, string? target, string? detailJson, string? remoteIp,
        bool success, string? actorUsername, CancellationToken cancellationToken = default) =>
        AppendAuditAsync(action, category, target, detailJson, remoteIp, success, actorUsername, null, null, true, cancellationToken);

    internal async Task AppendAuditAsync(string action, string category, string? target, string? detailJson, string? remoteIp,
        bool success, string? actorUsername, string? traceId, string? result = null, bool publish = true,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await AppendAuditCoreAsync(connection, null, action, category, target, detailJson, remoteIp, success,
            actorUsername, cancellationToken).ConfigureAwait(false);
        if (publish)
        {
            var sourceId = action is "backup.create" or "logs.export" ? null : target;
            PublishAudit(action, sourceId, actorUsername, remoteIp, success, traceId, result);
        }
    }

    private static async Task AppendAuditCoreAsync(SqliteConnection connection, SqliteTransaction? transaction,
        string action, string category, string? target, string? detailJson, string? remoteIp, bool success,
        string? actorUsername, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO audit_records(occurred_at_utc, action, category, actor_username, target, detail_json, remote_ip, success) VALUES ($occurred, $action, $category, $actor, $target, $detail, $remoteIp, $success);";
        command.Parameters.AddWithValue("$occurred", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$action", action);
        command.Parameters.AddWithValue("$category", category);
        command.Parameters.AddWithValue("$actor", (object?)actorUsername ?? DBNull.Value);
        command.Parameters.AddWithValue("$target", (object?)target ?? DBNull.Value);
        command.Parameters.AddWithValue("$detail", (object?)detailJson ?? DBNull.Value);
        command.Parameters.AddWithValue("$remoteIp", (object?)remoteIp ?? DBNull.Value);
        command.Parameters.AddWithValue("$success", success ? 1 : 0);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = true,
            DefaultTimeout = 30
        }.ToString());
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var pragma = connection.CreateCommand();
        pragma.CommandText = "PRAGMA busy_timeout=10000; PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;";
        await pragma.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        return connection;
    }

    private static async Task<long> ScalarLongAsync(SqliteConnection connection, string sql, CancellationToken cancellationToken, params (string Name, object Value)[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        foreach (var parameter in parameters) command.Parameters.AddWithValue(parameter.Name, parameter.Value);
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture);
    }

    private static async Task<string?> ScalarStringAsync(SqliteConnection connection, string sql, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        return await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as string;
    }

    private static DateTimeOffset ParseUtc(string value) => DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind).ToUniversalTime();

    private static string NormalizeTrendRange(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "7d" => "7d",
        "1m" or "30d" => "1m",
        _ => "24h"
    };

    private static DateTimeOffset StartOfUtcDay(DateTimeOffset value) =>
        new(value.Year, value.Month, value.Day, 0, 0, 0, TimeSpan.Zero);

    private static DateTimeOffset? ParseNullableUtc(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : ParseUtc(value);

    private static string ResolvePath(string directory, string fileName, string contentRoot) =>
        Path.Combine(ResolveDirectory(directory, contentRoot), fileName);

    private static string ResolveDirectory(string path, string contentRoot) =>
        Path.IsPathRooted(path) ? path : Path.GetFullPath(Path.Combine(contentRoot, path));
}
