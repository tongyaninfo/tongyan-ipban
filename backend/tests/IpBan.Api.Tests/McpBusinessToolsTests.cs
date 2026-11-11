using System.Text.Json;
using IpBan.Api.Options;
using IpBan.Api.Service;
using IpBan.Api.Service.impl;
using IpBan.Api.Service.Mcp;
using IpBan.Shared.Logging;
using IpBan.Shared.Models;
using IpBan.Shared.Service;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;

namespace IpBan.Api.Tests;

public sealed class McpBusinessToolsTests
{
    [Theory]
    [InlineData("""{"sourceAddress":"0.0.0.0/0","durationSeconds":180,"reason":"test"}""", "INVALID_SOURCE_ADDRESS")]
    [InlineData("""{"sourceAddress":"192.0.2.10","durationSeconds":0,"reason":"test"}""", "INVALID_ARGUMENTS")]
    [InlineData("""{"sourceAddress":"192.0.2.10","durationSeconds":-1,"reason":"test"}""", "INVALID_ARGUMENTS")]
    [InlineData("""{"sourceAddress":"192.0.2.10","durationSeconds":180,"reason":"test","disconnectExisting":true}""", "INVALID_ARGUMENTS")]
    [InlineData("""{"sourceAddress":"192.0.2.10","sourceAddress":"192.0.2.11","durationSeconds":180,"reason":"test"}""", "INVALID_ARGUMENTS")]
    public async Task RejectsUnsafeBanArgumentsBeforeAgentDispatch(string arguments, string expectedCode)
    {
        var agent = new FakeAgent();
        var result = await InvokeAsync(CreateTools(agent), "create_ban", arguments);
        Assert.False(result.Success);
        Assert.Equal(expectedCode, result.Code);
        Assert.Null(agent.LastBan);
    }

    [Fact]
    public async Task FiniteBanDoesNotDisconnectAndReportsActualFirewallState()
    {
        var agent = new FakeAgent();
        var result = await InvokeAsync(CreateTools(agent), "create_ban",
            """{"sourceAddress":"192.0.2.10","durationSeconds":180,"reason":"合成登录失败"}""");
        Assert.Equal(("192.0.2.10", 180, false), agent.LastBan);
        Assert.False(result.Success);
        Assert.Equal("FIREWALL_DISABLED", result.Code);
        var data = Assert.IsType<JsonElement>(result.Data);
        var action = data.GetProperty("firewallAction");
        Assert.Equal((int)FirewallActionStatus.Disabled, action.GetProperty("actionStatus").GetInt32());
        Assert.Equal(JsonValueKind.Null, action.GetProperty("errorMessage").ValueKind);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PermanentBanUsesItsOwnAuthorizationAndNeverDisconnects(bool authorized)
    {
        var agent = new FakeAgent();
        using var arguments = JsonDocument.Parse("""{"sourceAddress":"192.0.2.0/24","reason":"合成登录失败"}""");
        var result = await CreateTools(agent).InvokeAsync("create_permanent_ban", arguments.RootElement, "test-key",
            _ => Task.FromResult(authorized), CancellationToken.None);

        Assert.Equal(authorized ? "FIREWALL_DISABLED" : "MCP_ACCESS_CHANGED", result.Code);
        if (authorized)
        {
            Assert.Equal(("192.0.2.0/24", ManualBanDuration.Permanent, false), agent.LastBan);
            var data = Assert.IsType<JsonElement>(result.Data);
            Assert.Equal(ManualBanDuration.Permanent, data.GetProperty("durationSeconds").GetInt32());
        }
        else
            Assert.Null(agent.LastBan);
    }

    [Fact]
    public async Task LoginEventKeepsExactIdAndHidesInternalEvidencePath()
    {
        var agent = new FakeAgent();
        var result = await InvokeAsync(CreateTools(agent), "list_login_events", """{"limit":1}""");
        Assert.True(result.Success);
        var item = Assert.IsType<JsonElement>(result.Data)[0];
        Assert.Equal("9007199254740993", item.GetProperty("id").GetString());
        Assert.Equal("sshd", item.GetProperty("localProcessName").GetString());
        Assert.Equal("file", item.GetProperty("evidenceSource").GetString());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DisconnectRechecksAuthorizationAfterSnapshotAndUsesExactOperation(bool authorized)
    {
        var snapshot = new ConnectionSnapshotContract("tcp", "ESTAB", "192.0.2.10", 40000, "192.0.2.1", 22,
            123, "sshd", DateTimeOffset.UtcNow);
        var agent = new FakeAgent { Connection = snapshot };
        var tools = CreateTools(agent);
        using var arguments = JsonDocument.Parse($$"""
            {"connectionId":"{{CurrentSessionProjector.BuildSessionId(snapshot)}}","observedAtUtc":"{{snapshot.ObservedAtUtc:O}}","reason":"test"}
            """);

        var result = await tools.InvokeAsync("disconnect_connection", arguments.RootElement, "test-key", _ =>
        {
            Assert.True(agent.SnapshotRead);
            return Task.FromResult(authorized);
        }, CancellationToken.None);

        Assert.Equal(authorized ? "OK" : "MCP_ACCESS_CHANGED", result.Code);
        Assert.Equal(authorized ? snapshot : null, agent.ExactDisconnected);
    }

    private static McpBusinessTools CreateTools(IAgentIpcClient agent)
    {
        var directory = Path.Combine(Path.GetTempPath(), "ipban-mcp-business-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var environment = WebApplication.CreateBuilder(new WebApplicationOptions { ContentRootPath = directory }).Environment;
        var store = new SqliteAdminStore(Microsoft.Extensions.Options.Options.Create(new ManagementDataOptions
        {
            DataDirectory = directory
        }), environment);
        return new McpBusinessTools(store, agent, new FileLogStore(new FileLoggingOptions(), directory),
            new ConfigurationBuilder().Build());
    }

    private static async Task<McpBusinessResult> InvokeAsync(McpBusinessTools tools, string name, string arguments)
    {
        using var json = JsonDocument.Parse(arguments);
        return await tools.InvokeAsync(name, json.RootElement, "test-key", CancellationToken.None);
    }

    internal sealed class FakeAgent : IAgentIpcClient
    {
        public (string Source, int DurationSeconds, bool DisconnectExisting)? LastBan { get; private set; }
        public ConnectionSnapshotContract? Connection { get; init; }
        public ConnectionSnapshotContract? ExactDisconnected { get; private set; }
        public bool SnapshotRead { get; private set; }

        public Task<ApiResult<ManualBanResult>> BanAsync(string sourceAddress, int durationSeconds, bool disconnectExisting,
            CancellationToken cancellationToken = default)
        {
            LastBan = (sourceAddress, durationSeconds, disconnectExisting);
            var firewall = new FirewallActionResult("fixture", sourceAddress, FirewallActionStatus.Disabled,
                FirewallStatus.Disabled, "FIREWALL_DISABLED", "internal provider detail", DateTimeOffset.UtcNow);
            return Task.FromResult(new ApiResult<ManualBanResult>(false, "FIREWALL_DISABLED", "fixture",
                new ManualBanResult(firewall, new ConnectionTerminationContract(false, 0, 0, null), durationSeconds)));
        }

        public Task<ApiResult<LoginEventContract[]>> ListLoginEventsAsync(int limit = 100,
            CancellationToken cancellationToken = default) => Task.FromResult(ApiResult<LoginEventContract[]>.Ok(
            [
                new LoginEventContract(9007199254740993, DateTimeOffset.UtcNow, ProtocolKind.Ssh, false,
                    "fixture", "192.0.2.10", 40000, "192.0.2.1", 22, 123, "/fixture/bin/sshd", null, null,
                    EventCompletenessLevel.Full, FieldAvailability.Available, FieldAvailability.Available,
                    FieldAvailability.Available, FieldAvailability.Available, "fixture", "fixture:1",
                    "file:/fixture/private/journal.log")
            ]));

        public Task<ApiResult<ConnectionSnapshotContract[]>> ListConnectionsAsync(CancellationToken cancellationToken = default)
        {
            SnapshotRead = true;
            return Task.FromResult(ApiResult<ConnectionSnapshotContract[]>.Ok(Connection is { } snapshot ? [snapshot] : []));
        }

        public Task<ApiResult<ConnectionTerminationContract>> DisconnectAsync(ConnectionSnapshotContract connection,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<ApiResult<ConnectionTerminationContract>> DisconnectExactAsync(ConnectionSnapshotContract connection,
            CancellationToken cancellationToken = default)
        {
            ExactDisconnected = connection;
            return Task.FromResult(ApiResult<ConnectionTerminationContract>.Ok(new ConnectionTerminationContract(true, 1, 1, null)));
        }

        public Task<ApiResult<FirewallActionResult>> UnbanAsync(string sourceAddress, long actionId,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<ApiResult<FirewallObservation>> ProbeFirewallAsync(CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }
}
