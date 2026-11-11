using IpBan.Shared.Logging.Syslog;
using IpBan.Api.Models;
using Microsoft.Data.Sqlite;

namespace IpBan.Api.Service.impl;

public sealed partial class SqliteAdminStore
{
    private async Task CommitAuditAsync(SqliteConnection connection, SqliteTransaction transaction, ManagementAuditContext? audit,
        string action, string category, string? target, CancellationToken cancellationToken)
    {
        if (audit is not null)
            await AppendAuditCoreAsync(connection, transaction, action, category, target, null, audit.RemoteIp, true,
                audit.Actor, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        if (audit is not null)
            PublishAudit(action, target, audit.Actor, audit.RemoteIp, traceId: audit.TraceId);
    }

    /// <summary>只投递审计元数据。详情字段可能包含配置内容、客户端输入和内部路径。</summary>
    internal void PublishAudit(string action, string? sourceId, string? actor, string? remoteIp,
        bool success = true, string? traceId = null, string? result = null)
    {
        if (_syslog is null) return;
        var (module, message, level) = action switch
        {
            "setup.initialize" => ("ipban-admin", "管理台初始化完成。", SyslogSeverity.Notice),
            "login.success" => ("ipban-login", "管理员登录成功。", SyslogSeverity.Notice),
            "login.failure" => ("ipban-login", "管理员登录失败。", SyslogSeverity.Emergency),
            "login.error" => ("ipban-login", "管理员登录处理异常。", SyslogSeverity.Emergency),
            "login.logout" => ("ipban-login", "管理员已退出登录。", SyslogSeverity.Notice),
            "user.upsert" => ("ipban-admin", "管理员账户已保存。", SyslogSeverity.Notice),
            "settings.update" => ("ipban-admin", "系统设置已更新。", SyslogSeverity.Notice),
            "access-list.upsert" or "mcp.access-list.upsert" => ("ipban-policy", "访问名单条目已保存。", SyslogSeverity.Notice),
            "access-list.delete" => ("ipban-policy", "访问名单条目已删除。", SyslogSeverity.Notice),
            "policy.upsert" or "mcp.policy.upsert" => ("ipban-policy", "封禁策略已保存。", SyslogSeverity.Notice),
            "policy.delete" => ("ipban-policy", "封禁策略已删除。", SyslogSeverity.Notice),
            "ban.create.request" or "mcp.ban.create.request" => ("ipban-ban", "已请求执行封禁。", SyslogSeverity.Emergency),
            "ban.create" or "mcp.ban.create" => ("ipban-ban", "封禁请求未取得可确认的执行结果。", SyslogSeverity.Emergency),
            "ban.unban.request" or "mcp.ban.unban.request" => ("ipban-unban", "已请求执行解封。", SyslogSeverity.Notice),
            "ban.unban" or "mcp.ban.unban" => ("ipban-unban", "解封请求未取得可确认的执行结果。", SyslogSeverity.Error),
            "session.disconnect.request" => ("ipban-session", "管理员请求断开当前连接。", SyslogSeverity.Notice),
            "session.disconnect" when success => ("ipban-session", "当前连接已断开。", SyslogSeverity.Notice),
            "session.disconnect" when result is "SESSION_NOT_FOUND" or "SESSION_CONNECTION_NOT_FOUND" => ("ipban-session", "连接或会话已结束。", SyslogSeverity.Informational),
            "session.disconnect" => ("ipban-session", "当前连接断开失败。", SyslogSeverity.Error),
            "backup.create" => ("ipban-backup", "数据库备份已生成。", SyslogSeverity.Notice),
            "certificate.upload" => ("ipban-cert", "管理台证书已保存。", SyslogSeverity.Notice),
            "logs.export" => ("ipban-logging", "系统日志已导出。", SyslogSeverity.Notice),
            "logs.file.delete.request" => ("ipban-logging", "已请求删除日志归档。", SyslogSeverity.Notice),
            "logs.file.delete" when success => ("ipban-logging", "日志归档已删除。", SyslogSeverity.Notice),
            "logs.file.delete" => ("ipban-logging", "日志归档未删除。", SyslogSeverity.Warning),
            "notifications.settings.update" => ("ipban-mail", "邮件通知配置已更新。", SyslogSeverity.Notice),
            "notifications.test" => ("ipban-mail", "测试邮件已排队。", SyslogSeverity.Notice),
            "ip-location.settings.update" => ("ipban-geoip", "IP 归属地配置已更新。", SyslogSeverity.Notice),
            "syslog.test.request" => ("ipban-syslog", "管理员已请求发送 Syslog 测试消息。", SyslogSeverity.Notice),
            "syslog.test.complete" when success => ("ipban-syslog", "Syslog 测试消息已发送。", SyslogSeverity.Notice),
            "syslog.test.complete" => ("ipban-syslog", "Syslog 测试发送失败。", SyslogSeverity.Warning),
            "mcp.start" => ("ipban-mcp", "MCP 服务已启用。", SyslogSeverity.Notice),
            "mcp.stop" => ("ipban-mcp", "MCP 服务已停用。", SyslogSeverity.Notice),
            "mcp.retention.update" => ("ipban-mcp", "MCP 审计留存期限已更新。", SyslogSeverity.Notice),
            "mcp.key.create" => ("ipban-mcp", "MCP 访问凭据已创建。", SyslogSeverity.Notice),
            "mcp.key.revoke" => ("ipban-mcp", "MCP 访问凭据已吊销。", SyslogSeverity.Notice),
            "mcp.key.delete" => ("ipban-mcp", "MCP 访问凭据记录已删除。", SyslogSeverity.Notice),
            "mcp.key.copy" => ("ipban-mcp", "管理员已读取 MCP 访问凭据。", SyslogSeverity.Notice),
            _ => ("ipban-audit", "管理操作已写入审计记录。", success ? SyslogSeverity.Notice : SyslogSeverity.Warning)
        };
        var isPriority = level == SyslogSeverity.Emergency || module == "ipban-unban";
        var entry = _syslog.CreateEvent(module, action, level, message, isPriority,
            result ?? (success ? "success" : "failed"), sourceId, remoteIp, actor, traceId: traceId);
        // 同一个账户、名单或策略可以有多次独立审计，目标标识不能用作审计去重键。
        _syslog.Publish(entry with { EventUid = Guid.NewGuid().ToString("N") });
    }
}
