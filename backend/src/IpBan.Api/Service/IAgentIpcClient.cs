using IpBan.Shared.Models;
using IpBan.Shared.Logging.Syslog;

namespace IpBan.Api.Service;

public interface IAgentIpcClient
{
    Task<ApiResult<ConnectionSnapshotContract[]>> ListConnectionsAsync(
        CancellationToken cancellationToken = default);

    Task<ApiResult<LoginEventContract[]>> ListLoginEventsAsync(
        int limit = 100,
        CancellationToken cancellationToken = default);

    Task<ApiResult<ManualBanResult>> BanAsync(
        string sourceAddress,
        int durationSeconds,
        bool disconnectExisting,
        CancellationToken cancellationToken = default);

    Task<ApiResult<ManualBanResult>> BanAsync(string sourceAddress, int durationSeconds, bool disconnectExisting,
        string? traceId, CancellationToken cancellationToken) => BanAsync(sourceAddress, durationSeconds, disconnectExisting, cancellationToken);

    Task<ApiResult<ConnectionTerminationContract>> DisconnectAsync(
        ConnectionSnapshotContract connection,
        CancellationToken cancellationToken = default);

    Task<ApiResult<ConnectionTerminationContract>> DisconnectExactAsync(
        ConnectionSnapshotContract connection,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(ApiResult<ConnectionTerminationContract>.Fail("UNSUPPORTED_OPERATION", "Agent 不支持精确下线。"));

    Task<ApiResult<FirewallActionResult>> UnbanAsync(string sourceAddress, long actionId,
        CancellationToken cancellationToken = default);

    Task<ApiResult<FirewallActionResult>> UnbanAsync(string sourceAddress, long actionId, string? traceId,
        CancellationToken cancellationToken) => UnbanAsync(sourceAddress, actionId, cancellationToken);

    Task<ApiResult<FirewallObservation>> ProbeFirewallAsync(
        CancellationToken cancellationToken = default);

    Task<ApiResult<SyslogProcessStatus>> GetSyslogStatusAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(ApiResult<SyslogProcessStatus>.Fail("UNSUPPORTED_OPERATION", "Agent 不支持查询 Syslog 状态。"));
}
