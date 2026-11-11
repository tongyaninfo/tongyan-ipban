using System.Globalization;
using System.Net.Sockets;
using System.Security.Authentication;
using IpBan.Api.Models;
using IpBan.Shared.Logging.Syslog;
using IpBan.Shared.Service;

namespace IpBan.Api.Service.impl;

public sealed class SyslogManagementService(SqliteAdminStore store, SyslogRuntime runtime, IAgentIpcClient agent,
    IIdService ids, TimeProvider clock) : IDisposable
{
    private readonly SemaphoreSlim configurationGate = new(1, 1);
    private readonly SemaphoreSlim testGate = new(1, 1);
    private DateTimeOffset nextTestUtc;

    public Task<SyslogSettings> GetAsync(CancellationToken cancellationToken) => store.ReadSyslogSettingsAsync(cancellationToken);

    public async Task<SyslogSettings> SaveAsync(SyslogSettings candidate, string actor, string? remoteIp, CancellationToken cancellationToken)
    {
        if (!SyslogConfiguration.TryNormalize(candidate, out var settings, out var message))
            throw new SyslogRequestException(400, "INVALID_SYSLOG_SETTINGS", message);

        await configurationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var saved = await store.SaveSyslogSettingsAsync(settings, actor, remoteIp, ids, clock.GetUtcNow(), cancellationToken)
                .ConfigureAwait(false);
            runtime.Apply(saved);
            var ignored = (saved.Targets ?? []).Count(target => target.IgnoreSslErrors);
            runtime.Publish("ipban-syslog", "syslog.settings.update", SyslogSeverity.Notice,
                $"Syslog 配置已更新，跳过服务器证书校验的目标数：{ignored.ToString(CultureInfo.InvariantCulture)}。",
                sourceId: saved.ConfigRevision, actor: actor, remoteIp: remoteIp, result: "saved");
            return saved;
        }
        finally { configurationGate.Release(); }
    }

    public async Task<SyslogStatusResult> GetStatusAsync(CancellationToken cancellationToken)
    {
        var desired = await GetAsync(cancellationToken).ConfigureAwait(false);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(2));
        try
        {
            var status = await agent.GetSyslogStatusAsync(deadline.Token).ConfigureAwait(false);
            return new(desired.ConfigRevision, runtime.Snapshot(), status.Success ? status.Data : null,
                status.Success ? null : status.Code);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new(desired.ConfigRevision, runtime.Snapshot(), null, "AGENT_IPC_TIMEOUT");
        }
    }

    public async Task<SyslogTestResult> TestAsync(SyslogTestRequest request, string actor, string? remoteIp,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.TargetId) || request.TargetId.Length > 64
            || string.IsNullOrWhiteSpace(request.ConfigRevision) || request.ConfigRevision.Length > 64)
            throw new SyslogRequestException(400, "INVALID_SYSLOG_TEST", "请选择已保存的 Syslog 目标和配置版本。");

        if (!testGate.Wait(0, cancellationToken)) throw TestRateLimit();
        try
        {
            if (clock.GetUtcNow() < nextTestUtc) throw TestRateLimit();
            await configurationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var settings = await GetAsync(cancellationToken).ConfigureAwait(false);
                if (!string.Equals(settings.ConfigRevision, request.ConfigRevision, StringComparison.Ordinal))
                    throw new SyslogRequestException(409, "SYSLOG_SETTINGS_CHANGED", "Syslog 配置已被修改，请刷新后重新测试。");
                var target = (settings.Targets ?? []).FirstOrDefault(item => item.Id == request.TargetId)
                    ?? throw new SyslogRequestException(404, "SYSLOG_TARGET_NOT_FOUND", "该 Syslog 目标不存在。");

                var testId = ids.NewId.ToString(CultureInfo.InvariantCulture);
                await store.AppendAuditAsync("syslog.test.request", "syslog", testId, null, remoteIp, true, actor, cancellationToken)
                    .ConfigureAwait(false);
                nextTestUtc = clock.GetUtcNow().AddSeconds(5);
                return await SendTestAsync(target, testId, actor, remoteIp, cancellationToken).ConfigureAwait(false);
            }
            finally { configurationGate.Release(); }
        }
        finally { testGate.Release(); }
    }

    private async Task<SyslogTestResult> SendTestAsync(SyslogTarget target, string testId, string actor, string? remoteIp,
        CancellationToken cancellationToken)
    {
        var evt = runtime.CreateEvent("ipban-syslog", "syslog.test", SyslogSeverity.Notice,
            "这是一条通研 IPBan Syslog 测试日志。", sourceId: testId, protocol: target.Protocol) with { EventUid = testId };
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        string stage;
        string message;
        try
        {
            await using var transport = new SyslogTransport(target);
            var acknowledged = await transport.SendAsync(evt, deadline.Token).ConfigureAwait(false);
            (stage, message) = target.Protocol switch
            {
                "udp" => ("udpSent", "消息已交给本机网络栈，请在接收端确认。"),
                "tcp" => ("tcpWritten", "TCP 已连接并完成本地写入，请在接收端确认。"),
                "tls" => ("tlsWritten", "TLS 握手和本地写入完成，请在接收端确认。"),
                "relp" when acknowledged => ("relpAcknowledged", "已收到 RELP 事务的正向应答。"),
                _ => throw new IOException("未收到预期的 Syslog 协议应答。")
            };
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            await RecordTestFailureAsync(testId, actor, remoteIp).ConfigureAwait(false);
            throw new SyslogRequestException(504, "SYSLOG_TEST_TIMEOUT", "Syslog 测试连接或发送超时。");
        }
        catch (TimeoutException)
        {
            await RecordTestFailureAsync(testId, actor, remoteIp).ConfigureAwait(false);
            throw new SyslogRequestException(504, "SYSLOG_TEST_TIMEOUT", "Syslog 测试连接或发送超时。");
        }
        catch (OperationCanceledException)
        {
            await RecordTestFailureAsync(testId, actor, remoteIp).ConfigureAwait(false);
            throw;
        }
        catch (AuthenticationException)
        {
            await RecordTestFailureAsync(testId, actor, remoteIp).ConfigureAwait(false);
            throw new SyslogRequestException(502, "SYSLOG_TEST_TLS_FAILED", "Syslog TLS 证书校验或握手失败。");
        }
        catch (Exception error) when (error is SocketException or IOException)
        {
            await RecordTestFailureAsync(testId, actor, remoteIp).ConfigureAwait(false);
            throw new SyslogRequestException(502, "SYSLOG_TEST_FAILED", "Syslog 目标连接、写入或协议应答失败。");
        }
        var completed = clock.GetUtcNow();
        await store.AppendAuditAsync("syslog.test.complete", "syslog", testId, null, remoteIp, true, actor, CancellationToken.None)
            .ConfigureAwait(false);
        return new(testId, target.Id, target.Protocol, stage, message, completed);
    }

    private Task RecordTestFailureAsync(string id, string actor, string? remoteIp) =>
        store.AppendAuditAsync("syslog.test.complete", "syslog", id, null, remoteIp, false, actor, CancellationToken.None);

    private static SyslogRequestException TestRateLimit() =>
        new(429, "SYSLOG_TEST_RATE_LIMITED", "已有测试正在运行或刚刚完成，请稍后重试。");

    public void Dispose()
    {
        configurationGate.Dispose();
        testGate.Dispose();
    }
}

public sealed class SyslogSettingsReader(SqliteAdminStore store) : ISyslogSettingsReader
{
    public Task<SyslogSettings> ReadAsync(CancellationToken cancellationToken) => store.ReadSyslogSettingsAsync(cancellationToken);
}

public sealed class SyslogRequestException(int status, string code, string message) : Exception(message)
{
    public int Status { get; } = status;
    public string Code { get; } = code;
}
