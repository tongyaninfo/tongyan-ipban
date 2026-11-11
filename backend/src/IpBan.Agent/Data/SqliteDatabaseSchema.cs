namespace IpBan.Agent.Data;

public static class SqliteDatabaseSchema
{
    public const int CurrentVersion = 7;

    public static IReadOnlyList<string> GetMigrationStatements(int version) => version switch
    {
        1 => MigrationV1,
        2 => MigrationV2,
        3 => MigrationV3,
        4 => MigrationV4,
        5 => MigrationV5,
        6 => MigrationV6,
        7 => MigrationV7,
        _ => throw new ArgumentOutOfRangeException(nameof(version), version, "未知的数据库迁移版本。")
    };

    private static readonly string[] MigrationV1 =
    [
        """
        CREATE TABLE IF NOT EXISTS login_events (
            id INTEGER NOT NULL PRIMARY KEY,
            occurred_at_utc TEXT NOT NULL,
            protocol TEXT NOT NULL,
            is_success INTEGER NOT NULL,
            username TEXT NULL,
            remote_ip TEXT NULL,
            remote_ip_availability TEXT NOT NULL,
            remote_port INTEGER NULL,
            local_ip TEXT NULL,
            local_port INTEGER NULL,
            local_process_id INTEGER NULL,
            local_process_name TEXT NULL,
            origin_process_id INTEGER NULL,
            origin_process_name TEXT NULL,
            completeness_level TEXT NOT NULL,
            username_availability TEXT NOT NULL,
            endpoint_availability TEXT NOT NULL,
            process_availability TEXT NOT NULL,
            collector TEXT NOT NULL,
            raw_event_id TEXT NULL,
            evidence_source TEXT NOT NULL
        );
        """,
        "CREATE INDEX IF NOT EXISTS ix_login_events_remote_ip_occurred_at ON login_events(remote_ip, occurred_at_utc);",
        """
        CREATE TABLE IF NOT EXISTS connection_snapshots (
            id INTEGER NOT NULL PRIMARY KEY,
            protocol TEXT NOT NULL,
            state TEXT NOT NULL,
            remote_ip TEXT NOT NULL,
            remote_port INTEGER NULL,
            local_ip TEXT NULL,
            local_port INTEGER NULL,
            process_id INTEGER NULL,
            process_name TEXT NULL,
            observed_at_utc TEXT NOT NULL
        );
        """,
        "CREATE INDEX IF NOT EXISTS ix_connection_snapshots_observed_at ON connection_snapshots(observed_at_utc);",
        """
        CREATE TABLE IF NOT EXISTS login_sessions (
            session_id TEXT NOT NULL PRIMARY KEY,
            protocol TEXT NOT NULL,
            username TEXT NULL,
            username_availability TEXT NOT NULL,
            remote_ip TEXT NOT NULL,
            remote_port INTEGER NULL,
            local_ip TEXT NULL,
            local_port INTEGER NULL,
            process_name TEXT NULL,
            process_availability TEXT NOT NULL,
            started_at_utc TEXT NOT NULL,
            last_observed_at_utc TEXT NULL,
            can_disconnect INTEGER NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS firewall_actions (
            id INTEGER NOT NULL PRIMARY KEY,
            source_ip TEXT NOT NULL,
            action TEXT NOT NULL,
            status TEXT NOT NULL,
            provider TEXT NOT NULL,
            error_code TEXT NULL,
            error_message TEXT NULL,
            created_at_utc TEXT NOT NULL,
            completed_at_utc TEXT NULL
        );
        """,
        "CREATE INDEX IF NOT EXISTS ix_firewall_actions_source_ip_created_at ON firewall_actions(source_ip, created_at_utc);"
    ];

    private static readonly string[] MigrationV2 =
    [
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER NOT NULL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at_utc TEXT NOT NULL,
            updated_at_utc TEXT NOT NULL,
            last_login_at_utc TEXT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER NOT NULL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            remote_ip TEXT NULL,
            created_at_utc TEXT NOT NULL,
            last_seen_at_utc TEXT NOT NULL,
            expires_at_utc TEXT NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """,
        "CREATE INDEX IF NOT EXISTS ix_user_sessions_user_expires ON user_sessions(user_id, expires_at_utc);",
        """
        CREATE TABLE IF NOT EXISTS system_settings (
            setting_key TEXT NOT NULL PRIMARY KEY,
            setting_value TEXT NULL,
            is_secret INTEGER NOT NULL DEFAULT 0,
            updated_at_utc TEXT NOT NULL,
            updated_by TEXT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS audit_records (
            id INTEGER NOT NULL PRIMARY KEY,
            occurred_at_utc TEXT NOT NULL,
            action TEXT NOT NULL,
            category TEXT NOT NULL,
            actor_user_id TEXT NULL,
            actor_username TEXT NULL,
            target TEXT NULL,
            detail_json TEXT NULL,
            remote_ip TEXT NULL,
            success INTEGER NOT NULL
        );
        """,
        "CREATE INDEX IF NOT EXISTS ix_audit_records_occurred_at ON audit_records(occurred_at_utc);",
        """
        CREATE TABLE IF NOT EXISTS certificate_metadata (
            id INTEGER NOT NULL PRIMARY KEY,
            certificate_path TEXT NOT NULL,
            subject TEXT NOT NULL,
            issuer TEXT NULL,
            thumbprint TEXT NOT NULL,
            not_before_utc TEXT NOT NULL,
            not_after_utc TEXT NOT NULL,
            uploaded_at_utc TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 0
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS backup_records (
            id INTEGER NOT NULL PRIMARY KEY,
            backup_kind TEXT NOT NULL,
            backup_path TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            sha256 TEXT NULL,
            created_at_utc TEXT NOT NULL,
            status TEXT NOT NULL,
            error_message TEXT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS log_rotation_records (
            id INTEGER NOT NULL PRIMARY KEY,
            log_path TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            compressed INTEGER NOT NULL,
            created_at_utc TEXT NOT NULL,
            deleted_at_utc TEXT NULL
        );
        """
    ];

    private static readonly string[] MigrationV3 =
    [
        """
        CREATE TABLE IF NOT EXISTS access_list_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT NOT NULL,
            entry_type TEXT NOT NULL,
            source TEXT NOT NULL,
            reason TEXT NULL,
            priority INTEGER NOT NULL DEFAULT 100,
            status TEXT NOT NULL DEFAULT 'Active',
            created_by TEXT NULL,
            created_at_utc TEXT NOT NULL,
            effective_at_utc TEXT NULL,
            expires_at_utc TEXT NULL,
            released_at_utc TEXT NULL
        );
        """,
        "CREATE INDEX IF NOT EXISTS ix_access_list_entries_address_status ON access_list_entries(address, status);",
        """
        CREATE TABLE IF NOT EXISTS ban_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            enabled INTEGER NOT NULL DEFAULT 1,
            threshold INTEGER NOT NULL,
            window_seconds INTEGER NOT NULL,
            observe_seconds INTEGER NOT NULL,
            cooldown_seconds INTEGER NOT NULL,
            ban_duration_seconds INTEGER NOT NULL,
            action TEXT NOT NULL DEFAULT 'Ban',
            protocol TEXT NULL,
            description TEXT NULL,
            version INTEGER NOT NULL DEFAULT 1,
            created_at_utc TEXT NOT NULL,
            updated_at_utc TEXT NOT NULL
        );
        """,
        "CREATE INDEX IF NOT EXISTS ix_ban_policies_enabled ON ban_policies(enabled);",
        "INSERT OR IGNORE INTO ban_policies(name, enabled, threshold, window_seconds, observe_seconds, cooldown_seconds, ban_duration_seconds, action, protocol, description, version, created_at_utc, updated_at_utc) VALUES ('SSH brute force', 1, 5, 300, 0, 900, 1800, 'Ban', 'Ssh', '连续失败达到阈值后封禁来源地址。', 1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));"
    ];

    // v4 用幂等补种修复早期 v3 数据库未写入内置策略的情况。
    private static readonly string[] MigrationV4 =
    [
        "INSERT OR IGNORE INTO ban_policies(name, enabled, threshold, window_seconds, observe_seconds, cooldown_seconds, ban_duration_seconds, action, protocol, description, version, created_at_utc, updated_at_utc) VALUES ('SSH brute force', 1, 5, 300, 0, 900, 1800, 'Ban', 'Ssh', '连续失败达到阈值后封禁来源地址。', 1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));"
    ];

    // v5 增加覆盖全部协议的内置策略，保留 SSH 专用策略供管理员分别启停和编辑。
    private static readonly string[] MigrationV5 =
    [
        "INSERT OR IGNORE INTO ban_policies(name, enabled, threshold, window_seconds, observe_seconds, cooldown_seconds, ban_duration_seconds, action, protocol, description, version, created_at_utc, updated_at_utc) VALUES ('All protocol brute force', 0, 5, 300, 0, 900, 1800, 'Ban', NULL, '跨协议失败达到阈值后封禁来源地址；默认停用，启用前请确认策略范围。', 1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));"
    ];

    private static readonly string[] MigrationV6 =
    [
        """
        CREATE TABLE IF NOT EXISTS mcp_settings (
            id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
            enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
            audit_retention_days INTEGER NOT NULL CHECK (audit_retention_days BETWEEN 1 AND 3650)
        );
        """,
        "INSERT OR IGNORE INTO mcp_settings(id, enabled, audit_retention_days) VALUES (1, 0, 30);",
        """
        CREATE TABLE IF NOT EXISTS mcp_api_keys (
            id INTEGER NOT NULL PRIMARY KEY,
            name TEXT NOT NULL,
            prefix TEXT NOT NULL,
            secret_hash TEXT NOT NULL UNIQUE,
            protected_secret BLOB NOT NULL,
            mode TEXT NOT NULL CHECK (mode IN ('read', 'write')),
            created_at_utc TEXT NOT NULL,
            expires_at_utc TEXT NULL,
            revoked_at_utc TEXT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS mcp_api_key_scopes (
            key_id INTEGER NOT NULL REFERENCES mcp_api_keys(id) ON DELETE CASCADE,
            scope TEXT NOT NULL,
            PRIMARY KEY (key_id, scope)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS mcp_call_audits (
            id INTEGER NOT NULL PRIMARY KEY,
            occurred_at_utc TEXT NOT NULL,
            key_id INTEGER NULL,
            key_name TEXT NULL,
            key_prefix TEXT NULL,
            trace_id TEXT NOT NULL,
            remote_ip TEXT NULL,
            path TEXT NOT NULL,
            method TEXT NULL,
            tool TEXT NULL,
            status TEXT NOT NULL CHECK (status IN ('pending', 'success', 'denied', 'error', 'uncertain')),
            http_status INTEGER NULL,
            duration_ms INTEGER NULL,
            request_headers TEXT NULL,
            request_body TEXT NULL,
            response_headers TEXT NULL,
            response_body TEXT NULL
        );
        """,
        "CREATE INDEX IF NOT EXISTS ix_mcp_call_audits_time ON mcp_call_audits(occurred_at_utc, id);",
        "CREATE INDEX IF NOT EXISTS ix_mcp_call_audits_key_time ON mcp_call_audits(key_id, occurred_at_utc, id);"
    ];

    // 通知候选与原始事件同事务记录，邮件发送及限流由管理 API 后台任务独立处理。
    private static readonly string[] MigrationV7 =
    [
        """
        CREATE TABLE IF NOT EXISTS notification_events (
            event_key TEXT NOT NULL PRIMARY KEY,
            event_type TEXT NOT NULL,
            group_key TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            config_revision TEXT NOT NULL,
            occurred_at_utc TEXT NOT NULL,
            created_at_utc TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            priority INTEGER NOT NULL DEFAULT 0
        );
        """,
        "CREATE INDEX IF NOT EXISTS ix_notification_events_status_created ON notification_events(status, created_at_utc);",
        "CREATE INDEX IF NOT EXISTS ix_notification_events_group_status ON notification_events(group_key, status);",
        """
        CREATE TABLE IF NOT EXISTS notification_outbox (
            id INTEGER NOT NULL PRIMARY KEY,
            event_type TEXT NOT NULL,
            group_key TEXT NOT NULL,
            config_revision TEXT NOT NULL,
            recipient TEXT NOT NULL,
            subject TEXT NOT NULL,
            html_body TEXT NOT NULL,
            text_body TEXT NOT NULL,
            template_version TEXT NOT NULL,
            message_id TEXT NOT NULL UNIQUE,
            payload_json TEXT NOT NULL,
            source_ip TEXT NULL,
            event_count INTEGER NOT NULL,
            status TEXT NOT NULL,
            priority INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            created_at_utc TEXT NOT NULL,
            expires_at_utc TEXT NOT NULL,
            next_attempt_at_utc TEXT NULL,
            sent_at_utc TEXT NULL,
            last_error_code TEXT NULL,
            last_error_message TEXT NULL,
            lease_until_utc TEXT NULL
        );
        """,
        "CREATE INDEX IF NOT EXISTS ix_notification_outbox_status_next ON notification_outbox(status, next_attempt_at_utc);",
        "CREATE INDEX IF NOT EXISTS ix_notification_outbox_created ON notification_outbox(created_at_utc);",
        "CREATE INDEX IF NOT EXISTS ix_notification_outbox_type_status ON notification_outbox(event_type, status);",
        """
        CREATE TABLE IF NOT EXISTS notification_rate_state (
            state_key TEXT NOT NULL PRIMARY KEY,
            window_start_utc TEXT NULL,
            count INTEGER NOT NULL DEFAULT 0,
            last_sent_at_utc TEXT NULL,
            suppressed_count INTEGER NOT NULL DEFAULT 0,
            updated_at_utc TEXT NOT NULL
        );
        """
    ];
}
