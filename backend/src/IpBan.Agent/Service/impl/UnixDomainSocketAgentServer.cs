#pragma warning disable CA1848, CA1873

using System.Net;
using System.Net.Sockets;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using IpBan.Agent.Options;
using IpBan.Agent.Service;
using IpBan.Shared.Models;
using IpBan.Shared.Logging.Syslog;
using IpBan.Shared.Serialization;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace IpBan.Agent.Service.impl;

/// <summary>
/// Agent 本机 Unix Domain Socket 服务。每个连接处理一条 JSON 请求和一条 JSON 响应。
/// </summary>
public sealed partial class UnixDomainSocketAgentServer(
    IConnectionSnapshotProvider snapshotProvider,
    IConnectionTerminator connectionTerminator,
    ILoginEventStore eventStore,
    IFirewallActionStore firewallActionStore,
    FirewallActionCoordinator actionCoordinator,
    IFirewallProviderSelector firewallProviderSelector,
    IHostEnvironment hostEnvironment,
    IOptions<AgentIpcOptions> options,
    ILogger<UnixDomainSocketAgentServer> logger,
    SyslogRuntime? syslog = null) : BackgroundService
{
    private readonly List<Task> _expiryTasks = [];
    private Socket? _listener;
    private string? _socketPath;
    private bool _socketCreated;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (OperatingSystem.IsWindows())
        {
            await ExecuteNamedPipeAsync(stoppingToken).ConfigureAwait(false);
            return;
        }

        if (!OperatingSystem.IsLinux())
        {
            LogUnsupportedPlatform();
            return;
        }

        _socketPath = ResolveSocketPath(options.Value.SocketPath, hostEnvironment.ContentRootPath);
        if (File.Exists(_socketPath))
        {
            LogSocketAlreadyExists(_socketPath);
            return;
        }

        var directory = Path.GetDirectoryName(_socketPath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        _listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        _listener.Bind(new UnixDomainSocketEndPoint(_socketPath));
        _listener.Listen(backlog: 32);
        _socketCreated = true;
        LogSocketListening(_socketPath);

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                Socket client;
                try
                {
                    client = await _listener.AcceptAsync(stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }

                _ = HandleClientAsync(client, stoppingToken);
            }
        }
        finally
        {
            _listener.Dispose();
            _listener = null;
            if (_socketCreated && _socketPath is not null)
            {
                try
                {
                    File.Delete(_socketPath);
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    LogSocketCleanupFailed(exception, _socketPath);
                }
            }
        }
    }

    private async Task ExecuteNamedPipeAsync(CancellationToken stoppingToken)
    {
        var pipeName = options.Value.PipeName;
        if (string.IsNullOrWhiteSpace(pipeName))
        {
            LogPipeNameInvalid();
            return;
        }

        LogNamedPipeListening(pipeName);
        while (!stoppingToken.IsCancellationRequested)
        {
            var pipe = new NamedPipeServerStream(
                pipeName,
                PipeDirection.InOut,
                NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous);
            try
            {
                await pipe.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);
                _ = HandleStreamAsync(pipe, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
                break;
            }
            catch (IOException exception)
            {
                pipe.Dispose();
                LogNamedPipeAcceptFailed(exception);
                if (!stoppingToken.IsCancellationRequested)
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(250), stoppingToken).ConfigureAwait(false);
                }
            }
        }
    }

    private async Task HandleClientAsync(Socket client, CancellationToken stoppingToken)
    {
        await HandleStreamAsync(new NetworkStream(client, ownsSocket: true), stoppingToken).ConfigureAwait(false);
    }

    private async Task HandleStreamAsync(Stream stream, CancellationToken stoppingToken)
    {
        await using var ownedStream = stream;
        using var reader = new StreamReader(ownedStream, Encoding.UTF8, detectEncodingFromByteOrderMarks: false);
        await using var writer = new StreamWriter(ownedStream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false))
        {
            AutoFlush = true
        };

        try
        {
            var line = await reader.ReadLineAsync(stoppingToken).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(line))
            {
                await WriteResponseAsync(writer, Failure("INVALID_REQUEST", "IPC 请求为空。"), stoppingToken)
                    .ConfigureAwait(false);
                return;
            }

            AgentIpcRequest? request;
            try
            {
                request = JsonSerializer.Deserialize(line, IpBanJsonContext.Default.AgentIpcRequest);
            }
            catch (JsonException)
            {
                request = null;
            }

            if (request is null)
            {
                await WriteResponseAsync(writer, Failure("INVALID_REQUEST", "IPC 请求 JSON 无效。"), stoppingToken)
                    .ConfigureAwait(false);
                return;
            }

            var response = request.Operation switch
            {
                AgentIpcOperations.ListConnections => await ListConnectionsAsync(stoppingToken).ConfigureAwait(false),
                AgentIpcOperations.ListLoginEvents => await ListLoginEventsAsync(request.Limit, stoppingToken).ConfigureAwait(false),
                AgentIpcOperations.Ban => await BanAsync(request, stoppingToken).ConfigureAwait(false),
                AgentIpcOperations.Unban => await UnbanAsync(request, stoppingToken).ConfigureAwait(false),
                AgentIpcOperations.Disconnect => await DisconnectAsync(request, exact: false, stoppingToken).ConfigureAwait(false),
                AgentIpcOperations.DisconnectExact => await DisconnectAsync(request, exact: true, stoppingToken).ConfigureAwait(false),
                AgentIpcOperations.ProbeFirewall => await ProbeFirewallAsync(stoppingToken).ConfigureAwait(false),
                AgentIpcOperations.SyslogStatus => new AgentIpcResponse(true, "OK", "已读取转发状态。", [], [], null, null,
                    SyslogStatus: syslog?.Snapshot()),
                _ => Failure("UNSUPPORTED_OPERATION", "不支持的 IPC 操作。")
            };
            await WriteResponseAsync(writer, response, stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Agent 停止时不再向客户端报告异常。
        }
        catch (IOException exception)
        {
            LogClientDisconnected(exception);
        }
        catch (Exception exception)
        {
            LogRequestFailed(exception);
            try
            {
                await WriteResponseAsync(writer, Failure("AGENT_IPC_ERROR", "Agent IPC 请求处理失败。"), stoppingToken)
                    .ConfigureAwait(false);
            }
            catch (Exception writeException) when (writeException is IOException or ObjectDisposedException)
            {
                logger.LogDebug(writeException, "Agent IPC 错误响应发送失败。");
            }
        }
    }

    private async Task<AgentIpcResponse> ListConnectionsAsync(CancellationToken cancellationToken)
    {
        try
        {
            var connections = (await snapshotProvider.QueryAsync(cancellationToken).ConfigureAwait(false)).ToArray();
            return new AgentIpcResponse(true, "OK", "当前连接查询成功。", connections, [], null, null);
        }
        catch (Exception exception) when (exception is InvalidOperationException or IOException)
        {
                LogConnectionQueryFailed(exception);
            return Failure("AGENT_CONNECTION_QUERY_FAILED", "当前连接查询失败。");
        }
    }

    private async Task<AgentIpcResponse> ListLoginEventsAsync(
        int? limit,
        CancellationToken cancellationToken)
    {
        try
        {
            var events = (await eventStore.QueryRecentAsync(
                Math.Clamp(limit ?? 100, 1, 1000),
                cancellationToken).ConfigureAwait(false)).ToArray();
            // Windows EventLog 和部分 Linux 日志没有本地端点；用同一时刻的连接快照补齐
            // 当前仍存续连接的本地 IP、端口和服务进程。无法关联时保留原始缺口，不伪造 Unknown。
            try
            {
                var connections = await snapshotProvider.QueryAsync(cancellationToken).ConfigureAwait(false);
                events = events
                    .Select(loginEvent => EnrichLoginEvent(loginEvent, connections))
                    .ToArray();
            }
            catch (Exception exception) when (exception is InvalidOperationException or IOException)
            {
                LogLoginEventEnrichmentFailed(exception);
            }

            return new AgentIpcResponse(true, "OK", "登录事件查询成功。", [], events, null, null);
        }
        catch (Exception exception) when (exception is InvalidOperationException or IOException)
        {
            LogLoginEventQueryFailed(exception);
            return Failure("AGENT_LOGIN_EVENT_QUERY_FAILED", "登录事件查询失败。");
        }
    }

    private static LoginEventContract EnrichLoginEvent(
        LoginEventContract loginEvent,
        IReadOnlyList<ConnectionSnapshotContract> connections)
    {
        if (string.IsNullOrWhiteSpace(loginEvent.RemoteIp))
        {
            return loginEvent;
        }

        var candidates = connections
            .Where(connection =>
                connection.State.Equals("ESTAB", StringComparison.OrdinalIgnoreCase)
                && string.Equals(connection.RemoteIp, loginEvent.RemoteIp, StringComparison.OrdinalIgnoreCase)
                && (loginEvent.RemotePort is null || connection.RemotePort == loginEvent.RemotePort))
            .OrderByDescending(connection => loginEvent.RemotePort is not null && connection.RemotePort == loginEvent.RemotePort)
            .ThenByDescending(connection => loginEvent.LocalProcessId is not null && connection.ProcessId == loginEvent.LocalProcessId)
            .ToArray();
        var connection = candidates.FirstOrDefault();
        if (connection is null)
        {
            return loginEvent;
        }

        var localProcessName = string.IsNullOrWhiteSpace(loginEvent.LocalProcessName)
            ? connection.ProcessName
            : loginEvent.LocalProcessName;
        var processAvailability = string.IsNullOrWhiteSpace(localProcessName)
            ? loginEvent.ProcessAvailability
            : FieldAvailability.Available;
        var endpointAvailability = loginEvent.RemotePort is not null
            && !string.IsNullOrWhiteSpace(connection.LocalIp)
            && connection.LocalPort is not null
            ? FieldAvailability.Available
            : loginEvent.EndpointAvailability;
        var completeness = loginEvent.CompletenessLevel;
        if (loginEvent.UsernameAvailability == FieldAvailability.Available
            && loginEvent.RemoteIpAvailability == FieldAvailability.Available
            && loginEvent.RemotePort is not null
            && endpointAvailability == FieldAvailability.Available
            && processAvailability == FieldAvailability.Available)
        {
            completeness = EventCompletenessLevel.Full;
        }

        return loginEvent with
        {
            LocalIp = connection.LocalIp,
            LocalPort = connection.LocalPort,
            LocalProcessId = loginEvent.LocalProcessId ?? connection.ProcessId,
            LocalProcessName = localProcessName,
            ProcessAvailability = processAvailability,
            EndpointAvailability = endpointAvailability,
            CompletenessLevel = completeness
        };
    }

    private async Task<AgentIpcResponse> ProbeFirewallAsync(CancellationToken cancellationToken)
    {
        try
        {
            var platform = OperatingSystem.IsWindows() ? "windows" : OperatingSystem.IsLinux() ? "linux" : "unsupported";
            var selection = await firewallProviderSelector.SelectAsync(platform, cancellationToken).ConfigureAwait(false);
            return new AgentIpcResponse(true, "OK", "防火墙状态查询成功。", [], [], null, null, selection.Observation);
        }
        catch (Exception exception) when (exception is InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            LogFirewallProbeFailed(exception);
            return Failure("FIREWALL_PROBE_FAILED", "防火墙状态查询失败。");
        }
    }

    private async Task<AgentIpcResponse> UnbanAsync(AgentIpcRequest request, CancellationToken cancellationToken)
    {
        var result = await actionCoordinator.UnbanAsync(request.ActionId ?? 0, request.SourceAddress ?? string.Empty,
            cancellationToken, request.TraceId).ConfigureAwait(false);
        return new AgentIpcResponse(result.Success, result.Code, result.Message, [], [], null, null, UnbanResult: result.Data);
    }

    internal async Task<AgentIpcResponse> BanAsync(
        AgentIpcRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.SourceAddress))
        {
            return Failure("INVALID_SOURCE_ADDRESS", "封禁来源地址不能为空。");
        }

        var durationSeconds = request.DurationSeconds.GetValueOrDefault(ManualBanDuration.DefaultSeconds);
        if (!ManualBanDuration.IsValid(durationSeconds))
        {
            return Failure("INVALID_DURATION", "封禁时长必须为 -1（永久）或 1 到 604800 秒。");
        }

        var sourceAddress = request.SourceAddress.Trim();
        if (durationSeconds == ManualBanDuration.Permanent
            && (!FirewallAddressValidator.TryNormalize(sourceAddress, out sourceAddress)
                || sourceAddress is "0.0.0.0" or "::"
                || sourceAddress.EndsWith("/0", StringComparison.Ordinal)))
        {
            return Failure("INVALID_SOURCE_ADDRESS", "永久封禁需要有效的单个 IP 或 CIDR，网段不能覆盖全部地址。");
        }

        var platform = OperatingSystem.IsWindows() ? "windows" : "linux";
        var selection = await firewallProviderSelector.SelectAsync(platform, cancellationToken)
            .ConfigureAwait(false);
        if (selection.Provider is null)
        {
            syslog?.Publish("ipban-ban", "ban.manual.decision", SyslogSeverity.Emergency, "已接收人工封禁决定。",
                result: "Decision", remoteIp: sourceAddress, traceId: request.TraceId);
            var unavailableAction = new FirewallActionResult(
                selection.Observation.Provider,
                sourceAddress,
                selection.Observation.Status == FirewallStatus.Disabled
                    ? FirewallActionStatus.Disabled
                    : FirewallActionStatus.Failed,
                selection.Observation.Status,
                $"FIREWALL_{selection.Observation.Status.ToString().ToUpperInvariant()}",
                selection.Observation.Detail,
                DateTimeOffset.UtcNow);
            await firewallActionStore.AppendAsync("ban", unavailableAction,
                new IpBan.Agent.Models.FirewallNotificationContext("人工封禁", durationSeconds, TraceId: request.TraceId), cancellationToken).ConfigureAwait(false);
            return new AgentIpcResponse(
                false,
                unavailableAction.ErrorCode ?? "FIREWALL_UNAVAILABLE",
                "未发现可用防火墙，未执行封禁。",
                [],
                [],
                new ManualBanResult(
                    unavailableAction,
                    new ConnectionTerminationContract(false, 0, 0, "防火墙未生效，未断开已有连接。"),
                    durationSeconds),
                null);
        }

        var recorded = await actionCoordinator.BanAsync(selection.Provider, sourceAddress, "ban", cancellationToken,
            notificationContext: new IpBan.Agent.Models.FirewallNotificationContext("人工封禁", durationSeconds, TraceId: request.TraceId))
            .ConfigureAwait(false);
        var firewallAction = recorded.Result;
        if (firewallAction.ActionStatus != FirewallActionStatus.Applied)
        {
            return new AgentIpcResponse(
                false,
                firewallAction.ErrorCode ?? "FIREWALL_ACTION_FAILED",
                "防火墙封禁未生效。",
                [],
                [],
                new ManualBanResult(
                    firewallAction,
                    new ConnectionTerminationContract(false, 0, 0, "防火墙封禁未生效，未断开已有连接。"),
                    durationSeconds),
                null);
        }

        if (durationSeconds > 0)
        {
            ScheduleUnban(
                selection.Provider,
                firewallAction.SourceAddress,
                recorded.Id,
                durationSeconds,
                request.DisconnectExisting,
                cancellationToken);
        }

        var termination = new ConnectionTerminationResult(true, 0, 0, null);
        if (request.DisconnectExisting && IPAddress.TryParse(firewallAction.SourceAddress, out var sourceIp))
        {
            await actionCoordinator.WhileCurrentAsync(firewallAction.SourceAddress, recorded.Id, async () =>
            {
                var existingConnections = await snapshotProvider.QueryAsync(cancellationToken).ConfigureAwait(false);
                var matchingConnections = existingConnections
                    .Where(connection => IPAddress.TryParse(connection.RemoteIp, out var remoteIp)
                        && remoteIp.Equals(sourceIp))
                    .ToArray();
                termination = await connectionTerminator.TerminateAsync(matchingConnections, cancellationToken)
                    .ConfigureAwait(false);
            }, cancellationToken).ConfigureAwait(false);
        }

        var result = new ManualBanResult(firewallAction, termination.ToContract(), durationSeconds);
        return new AgentIpcResponse(
            Success: termination.Success,
            Code: termination.Success ? "OK" : "CONNECTION_TERMINATION_FAILED",
            Message: termination.Success
                ? (request.DisconnectExisting ? "防火墙封禁已生效，已有连接处置完成。" : "防火墙封禁已生效。")
                : "防火墙封禁已生效，但部分已有连接未能断开。",
            Connections: [],
            LoginEvents: [],
            BanResult: result,
            DisconnectionResult: null);
    }

    private async Task<AgentIpcResponse> DisconnectAsync(
        AgentIpcRequest request,
        bool exact,
        CancellationToken cancellationToken)
    {
        var target = request.Connection;
        if (target is null
            || string.IsNullOrWhiteSpace(target.RemoteIp)
            || target.RemotePort is null
            || string.IsNullOrWhiteSpace(target.LocalIp)
            || target.LocalPort is null)
        {
            return Failure("INVALID_CONNECTION", "下线请求缺少完整连接端点。");
        }

        if (IsManagementConnection(target))
        {
            return Failure("PROTECTED_CONNECTION", "不能通过当前接口下线 IPBan 管理连接。");
        }

        var currentConnections = await snapshotProvider.QueryAsync(cancellationToken).ConfigureAwait(false);
        var current = currentConnections
            .Where(connection => MatchesConnection(target, connection))
            .ToArray();
        if (current.Length == 0)
        {
            return Failure("CONNECTION_NOT_FOUND", "连接已不存在或快照已过期。");
        }

        ConnectionTerminationResult termination;
        if (exact)
        {
            if (current.Length != 1 || target.ProcessId is not > 0
                || !string.Equals(target.Protocol, "tcp", StringComparison.OrdinalIgnoreCase)
                || !string.Equals(target.State, "ESTAB", StringComparison.OrdinalIgnoreCase))
                return Failure("INVALID_CONNECTION", "精确下线需要唯一、完整的已建立 TCP 快照。");

            termination = await connectionTerminator.TerminateExactAsync(current[0], cancellationToken).ConfigureAwait(false);
            if (termination.Success)
            {
                // 某些内核会返回退出码 0，即使对应 socket 没有被销毁。核对四元组后才报告成功。
                var remaining = await snapshotProvider.QueryAsync(cancellationToken).ConfigureAwait(false);
                var endpoint = target with { ProcessId = null, ProcessName = null };
                if (remaining.Any(connection => MatchesConnection(endpoint, connection)))
                    termination = new ConnectionTerminationResult(false, 1, 0, "目标 TCP 连接仍在快照中，未确认下线。");
            }
        }
        else
        {
            termination = await connectionTerminator.TerminateExplicitAsync(current, cancellationToken).ConfigureAwait(false);
        }
        var contract = termination.ToContract();
        syslog?.Publish("ipban-session", "session.disconnect.result", termination.Success ? SyslogSeverity.Notice : SyslogSeverity.Error,
            termination.Success ? "已有连接已下线。" : "已有连接下线失败。", result: termination.Success ? "Success" : "Failure",
            remoteIp: target.RemoteIp, traceId: request.TraceId);
        return new AgentIpcResponse(
            Success: termination.Success,
            Code: termination.Success ? "OK" : "CONNECTION_TERMINATION_FAILED",
            Message: termination.Success ? "连接已下线。" : "连接下线失败。",
            Connections: [],
            LoginEvents: [],
            BanResult: null,
            DisconnectionResult: contract);
    }

    private static bool MatchesConnection(
        ConnectionSnapshotContract requested,
        ConnectionSnapshotContract current) =>
        current.State.Equals("ESTAB", StringComparison.OrdinalIgnoreCase)
        && current.Protocol.Equals(requested.Protocol, StringComparison.OrdinalIgnoreCase)
        && (string.IsNullOrWhiteSpace(requested.State)
            || current.State.Equals(requested.State, StringComparison.OrdinalIgnoreCase))
        && string.Equals(current.RemoteIp, requested.RemoteIp, StringComparison.OrdinalIgnoreCase)
        && current.RemotePort == requested.RemotePort
        && string.Equals(current.LocalIp, requested.LocalIp, StringComparison.OrdinalIgnoreCase)
        && current.LocalPort == requested.LocalPort
        && (requested.ProcessId is null || current.ProcessId == requested.ProcessId)
        && (string.IsNullOrWhiteSpace(requested.ProcessName)
            || current.ProcessName?.Equals(requested.ProcessName, StringComparison.OrdinalIgnoreCase) == true);

    private static bool IsManagementConnection(ConnectionSnapshotContract connection) =>
        connection.LocalPort == 5180
        || connection.ProcessName?.Contains("IpBan.Api", StringComparison.OrdinalIgnoreCase) == true
        || connection.ProcessName?.Contains("IpBan.Agent", StringComparison.OrdinalIgnoreCase) == true;

    private void ScheduleUnban(
        IFirewallProvider provider,
        string sourceAddress,
        long actionId,
        int durationSeconds,
        bool monitorExistingConnections,
        CancellationToken stoppingToken)
    {
        var expiryTask = Task.Run(async () =>
        {
            try
            {
                var expiresAtUtc = DateTimeOffset.UtcNow.AddSeconds(durationSeconds);
                if (monitorExistingConnections && IPAddress.TryParse(sourceAddress, out var sourceIp))
                {
                    while (DateTimeOffset.UtcNow < expiresAtUtc)
                    {
                        try
                        {
                            var current = await actionCoordinator.WhileCurrentAsync(sourceAddress, actionId, async () =>
                            {
                                var connections = await snapshotProvider.QueryAsync(stoppingToken).ConfigureAwait(false);
                                var matchingSshConnections = connections
                                    .Where(connection => IPAddress.TryParse(connection.RemoteIp, out var remoteIp)
                                        && remoteIp.Equals(sourceIp)
                                        && IsSshProcess(connection.ProcessName))
                                    .ToArray();
                                if (matchingSshConnections.Length > 0)
                                {
                                    await connectionTerminator.TerminateAsync(
                                        matchingSshConnections,
                                        stoppingToken).ConfigureAwait(false);
                                }
                            }, stoppingToken).ConfigureAwait(false);
                            if (!current) return;
                        }
                        catch (Exception exception) when (exception is InvalidOperationException or IOException)
                        {
                            LogBanMonitorFailed(exception, sourceAddress);
                        }

                        var remaining = expiresAtUtc - DateTimeOffset.UtcNow;
                        if (remaining <= TimeSpan.Zero)
                        {
                            break;
                        }

                        await Task.Delay(
                            remaining < TimeSpan.FromSeconds(1)
                                ? remaining
                                : TimeSpan.FromSeconds(1),
                            stoppingToken).ConfigureAwait(false);
                    }
                }
                else
                {
                    await Task.Delay(TimeSpan.FromSeconds(durationSeconds), stoppingToken).ConfigureAwait(false);
                }

                var result = await actionCoordinator.ExpireAsync(provider, sourceAddress, actionId, "unban", stoppingToken).ConfigureAwait(false);
                if (result is not null && result.ActionStatus != FirewallActionStatus.Removed)
                {
                    LogExpiryUnbanFailed(provider.Name, sourceAddress, result.ErrorCode);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                // Agent 停止时不自动恢复既有规则；本次临时任务随 Agent 结束。
            }
            catch (Exception exception)
            {
                LogExpiryUnbanException(exception, provider.Name, sourceAddress);
            }
        }, stoppingToken);
        lock (_expiryTasks)
        {
            _expiryTasks.Add(expiryTask);
        }
    }

    private static bool IsSshProcess(string? processName) =>
        !string.IsNullOrWhiteSpace(processName)
        && processName.Contains("ssh", StringComparison.OrdinalIgnoreCase);

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

    private static AgentIpcResponse Failure(string code, string message) =>
        new(false, code, message, [], [], null, null);

    private static async Task WriteResponseAsync(
        StreamWriter writer,
        AgentIpcResponse response,
        CancellationToken cancellationToken)
    {
        var json = JsonSerializer.Serialize(response, IpBanJsonContext.Default.AgentIpcResponse);
        await writer.WriteLineAsync(json).WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "当前平台不是 Linux，Agent Unix Socket IPC 不启动。")]
    private partial void LogUnsupportedPlatform();

    [LoggerMessage(Level = LogLevel.Information, Message = "Agent IPC Named Pipe 已监听: {PipeName}")]
    private partial void LogNamedPipeListening(string pipeName);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Agent IPC Named Pipe 接收连接失败。")]
    private partial void LogNamedPipeAcceptFailed(Exception exception);

    [LoggerMessage(Level = LogLevel.Error, Message = "AgentIpc:PipeName 不能为空，Named Pipe IPC 未启动。")]
    private partial void LogPipeNameInvalid();

    [LoggerMessage(Level = LogLevel.Error, Message = "Agent IPC socket 已存在，拒绝覆盖以避免接管其他进程: {SocketPath}")]
    private partial void LogSocketAlreadyExists(string socketPath);

    [LoggerMessage(Level = LogLevel.Information, Message = "Agent IPC Unix Socket 已监听: {SocketPath}")]
    private partial void LogSocketListening(string socketPath);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Agent IPC socket 清理失败: {SocketPath}")]
    private partial void LogSocketCleanupFailed(Exception exception, string socketPath);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Agent IPC 客户端已断开。")]
    private partial void LogClientDisconnected(Exception exception);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Agent IPC 请求处理失败。")]
    private partial void LogRequestFailed(Exception exception);

    [LoggerMessage(Level = LogLevel.Warning, Message = "当前连接查询失败。")]
    private partial void LogConnectionQueryFailed(Exception exception);

    [LoggerMessage(Level = LogLevel.Warning, Message = "登录事件查询失败。")]
    private partial void LogLoginEventQueryFailed(Exception exception);

    [LoggerMessage(Level = LogLevel.Debug, Message = "登录事件本地端点关联失败，本轮返回原始事件。")]
    private partial void LogLoginEventEnrichmentFailed(Exception exception);

    [LoggerMessage(Level = LogLevel.Warning, Message = "防火墙状态查询失败。")]
    private partial void LogFirewallProbeFailed(Exception exception);

    [LoggerMessage(Level = LogLevel.Warning, Message = "临时封禁到期解封失败: {Provider} {SourceAddress} {ErrorCode}")]
    private partial void LogExpiryUnbanFailed(string provider, string sourceAddress, string? errorCode);

    [LoggerMessage(Level = LogLevel.Warning, Message = "临时封禁到期解封异常: {Provider} {SourceAddress}")]
    private partial void LogExpiryUnbanException(Exception exception, string provider, string sourceAddress);

    [LoggerMessage(Level = LogLevel.Warning, Message = "临时封禁期间 SSH 连接巡检失败: {SourceAddress}")]
    private partial void LogBanMonitorFailed(Exception exception, string sourceAddress);
}
