#pragma warning disable CA1848

using System.Net.Sockets;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using IpBan.Api.Options;
using IpBan.Shared.Models;
using IpBan.Shared.Serialization;
using IpBan.Shared.Logging.Syslog;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace IpBan.Api.Service.impl;

/// <summary>
/// 管理 API 到 Agent 的单请求本机 IPC 客户端。
/// Linux 使用 Unix Domain Socket，Windows 使用 Named Pipe。
/// </summary>
public sealed class UnixDomainSocketAgentClient(
    IHostEnvironment hostEnvironment,
    IOptions<AgentIpcOptions> options,
    ILogger<UnixDomainSocketAgentClient> logger) : IAgentIpcClient
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(5);
    private readonly string _socketPath = OperatingSystem.IsWindows()
        ? string.Empty
        : ResolveSocketPath(options.Value.SocketPath, hostEnvironment.ContentRootPath);

    public Task<ApiResult<ConnectionSnapshotContract[]>> ListConnectionsAsync(
        CancellationToken cancellationToken = default) =>
        SendAsync<ConnectionSnapshotContract[]>(
            new AgentIpcRequest(AgentIpcOperations.ListConnections),
            response => response.Connections,
            "当前连接查询失败。",
            cancellationToken);

    public Task<ApiResult<ManualBanResult>> BanAsync(
        string sourceAddress,
        int durationSeconds,
        bool disconnectExisting,
        CancellationToken cancellationToken = default) => BanAsync(sourceAddress, durationSeconds, disconnectExisting, null, cancellationToken);

    public Task<ApiResult<ManualBanResult>> BanAsync(string sourceAddress, int durationSeconds, bool disconnectExisting,
        string? traceId, CancellationToken cancellationToken) =>
        SendAsync(
            new AgentIpcRequest(
                AgentIpcOperations.Ban,
                sourceAddress,
                durationSeconds,
                disconnectExisting, TraceId: traceId),
            response => response.BanResult,
            "封禁请求失败。",
            cancellationToken);

    public Task<ApiResult<LoginEventContract[]>> ListLoginEventsAsync(
        int limit = 100,
        CancellationToken cancellationToken = default) =>
        SendAsync(
            new AgentIpcRequest(AgentIpcOperations.ListLoginEvents, Limit: Math.Clamp(limit, 1, 1000)),
            response => response.LoginEvents,
            "登录事件查询失败。",
            cancellationToken);

    public Task<ApiResult<FirewallActionResult>> UnbanAsync(string sourceAddress, long actionId,
        CancellationToken cancellationToken = default) => UnbanAsync(sourceAddress, actionId, null, cancellationToken);

    public Task<ApiResult<FirewallActionResult>> UnbanAsync(string sourceAddress, long actionId, string? traceId,
        CancellationToken cancellationToken) => SendAsync(
            new AgentIpcRequest(AgentIpcOperations.Unban, SourceAddress: sourceAddress, ActionId: actionId, TraceId: traceId),
            response => response.UnbanResult, "手动解封失败。", cancellationToken);

    public Task<ApiResult<ConnectionTerminationContract>> DisconnectAsync(
        ConnectionSnapshotContract connection,
        CancellationToken cancellationToken = default) =>
        SendAsync(
            new AgentIpcRequest(AgentIpcOperations.Disconnect, Connection: connection),
            response => response.DisconnectionResult,
            "连接下线请求失败。",
            cancellationToken);

    public Task<ApiResult<ConnectionTerminationContract>> DisconnectExactAsync(
        ConnectionSnapshotContract connection,
        CancellationToken cancellationToken = default) =>
        SendAsync(
            new AgentIpcRequest(AgentIpcOperations.DisconnectExact, Connection: connection),
            response => response.DisconnectionResult,
            "精确下线请求失败。",
            cancellationToken);

    public Task<ApiResult<FirewallObservation>> ProbeFirewallAsync(
        CancellationToken cancellationToken = default) =>
        SendAsync(
            new AgentIpcRequest(AgentIpcOperations.ProbeFirewall),
            response => response.FirewallObservation,
            "防火墙状态查询失败。",
            cancellationToken);

    public Task<ApiResult<SyslogProcessStatus>> GetSyslogStatusAsync(CancellationToken cancellationToken = default) =>
        SendAsync(new AgentIpcRequest(AgentIpcOperations.SyslogStatus), response => response.SyslogStatus,
            "Agent Syslog 状态查询失败。", cancellationToken);

    private async Task<ApiResult<T>> SendAsync<T>(
        AgentIpcRequest request,
        Func<AgentIpcResponse, T?> dataSelector,
        string fallbackMessage,
        CancellationToken cancellationToken)
    {
        try
        {
            using var connectTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            connectTimeout.CancelAfter(ConnectTimeout);

            if (OperatingSystem.IsWindows())
            {
                using var pipe = new NamedPipeClientStream(
                    ".",
                    options.Value.PipeName,
                    PipeDirection.InOut,
                    PipeOptions.Asynchronous);
                await pipe.ConnectAsync(connectTimeout.Token).ConfigureAwait(false);
                return await SendOnStreamAsync(pipe, request, dataSelector, fallbackMessage, cancellationToken).ConfigureAwait(false);
            }

            if (!OperatingSystem.IsLinux())
            {
                return ApiResult<T>.Fail("AGENT_IPC_UNAVAILABLE", "当前平台不支持 Agent IPC。");
            }

            using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            await socket.ConnectAsync(new UnixDomainSocketEndPoint(_socketPath), connectTimeout.Token)
                .ConfigureAwait(false);

            await using var stream = new NetworkStream(socket, ownsSocket: true);
            return await SendOnStreamAsync(stream, request, dataSelector, fallbackMessage, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return ApiResult<T>.Fail("AGENT_IPC_TIMEOUT", "Agent IPC 请求超时。");
        }
        catch (TimeoutException exception)
        {
            logger.LogWarning(exception, "Agent IPC 连接超时。");
            return ApiResult<T>.Fail("AGENT_IPC_TIMEOUT", "Agent IPC 请求超时。");
        }
        catch (SocketException exception)
        {
            logger.LogWarning(exception, "Agent IPC socket 不可用: {SocketPath}", _socketPath);
            return ApiResult<T>.Fail("AGENT_IPC_UNAVAILABLE", "Agent IPC 不可用。");
        }
        catch (UnauthorizedAccessException exception)
        {
            logger.LogWarning(exception, "Agent IPC 权限不足。");
            return ApiResult<T>.Fail("AGENT_IPC_UNAVAILABLE", "Agent IPC 权限不足。");
        }
        catch (IOException exception)
        {
            logger.LogWarning(exception, "Agent IPC 通信失败: {SocketPath}", _socketPath);
            return ApiResult<T>.Fail("AGENT_IPC_UNAVAILABLE", "Agent IPC 通信失败。");
        }
        catch (JsonException exception)
        {
            logger.LogWarning(exception, "Agent IPC 响应 JSON 无效。");
            return ApiResult<T>.Fail("AGENT_IPC_INVALID_RESPONSE", fallbackMessage);
        }
    }

    private static async Task<ApiResult<T>> SendOnStreamAsync<T>(
        Stream stream,
        AgentIpcRequest request,
        Func<AgentIpcResponse, T?> dataSelector,
        string fallbackMessage,
        CancellationToken cancellationToken)
    {
        await using var writer = new StreamWriter(
            stream,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
            bufferSize: 1024,
            leaveOpen: true)
        {
            AutoFlush = true
        };
            // Reader 和 Writer 都不拥有底层 IPC 流；由调用方统一释放 Socket/Named Pipe。
            // 否则 reader 先释放会关闭 pipe，writer 的异步释放会抛 ObjectDisposedException。
            using var reader = new StreamReader(
                stream,
                Encoding.UTF8,
                detectEncodingFromByteOrderMarks: false,
                bufferSize: 1024,
                leaveOpen: true);

        var json = JsonSerializer.Serialize(request, IpBanJsonContext.Default.AgentIpcRequest);
        await writer.WriteLineAsync(json).WaitAsync(cancellationToken).ConfigureAwait(false);
        var line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(line))
        {
            return ApiResult<T>.Fail("AGENT_IPC_EMPTY_RESPONSE", fallbackMessage);
        }

        var response = JsonSerializer.Deserialize(line, IpBanJsonContext.Default.AgentIpcResponse);
        if (response is null)
        {
            return ApiResult<T>.Fail("AGENT_IPC_INVALID_RESPONSE", fallbackMessage);
        }

        var data = dataSelector(response);
        if (response.Success && data is not null)
        {
            return ApiResult<T>.Ok(data, response.Message);
        }

        if (data is not null)
        {
            // 保留 FirewallFailed/Disabled 与已有连接处置明细，便于管理台区分降级状态。
            return new ApiResult<T>(false, response.Code, response.Message, data);
        }

        return ApiResult<T>.Fail(response.Code, response.Message);
    }

    private static string ResolveSocketPath(string configuredPath, string contentRoot)
    {
        if (string.IsNullOrWhiteSpace(configuredPath))
        {
            throw new InvalidOperationException("AgentIpc:SocketPath 不能为空。");
        }

        return Path.IsPathRooted(configuredPath)
            ? configuredPath
            : Path.GetFullPath(Path.Combine(contentRoot, configuredPath));
    }
}
