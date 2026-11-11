using IpBan.Shared.Logging.Syslog;

namespace IpBan.Agent.Service.impl;

/// <summary>同一日志源只在首次故障、持续降级或恢复时记录，避免轮询刷屏。</summary>
internal sealed class CollectorLogHealth(SyslogRuntime? syslog, string source)
{
    private int failures;
    private DateTimeOffset firstFailure;
    private bool escalated;

    public void Failed(bool permanent = false)
    {
        var now = DateTimeOffset.UtcNow;
        if (failures == 0) firstFailure = now;
        if (failures < int.MaxValue) failures++;
        var error = permanent || failures >= 3 || now - firstFailure >= TimeSpan.FromMinutes(1);
        if ((error && !escalated) || failures == 1)
            syslog?.Publish("ipban-collector", "collector.source.failed",
                error ? SyslogSeverity.Error : SyslogSeverity.Warning,
                $"无法读取 {source} 登录日志源。", result: "Unavailable");
        escalated |= error;
    }

    public void Recovered()
    {
        if (failures == 0) return;
        failures = 0;
        escalated = false;
        syslog?.Publish("ipban-collector", "collector.source.recovered", SyslogSeverity.Notice,
            $"{source} 登录日志源已恢复。", result: "Recovered");
    }
}
