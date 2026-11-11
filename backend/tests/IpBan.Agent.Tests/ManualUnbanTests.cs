using System.Text.Json;
using IpBan.Agent.Options;
using IpBan.Agent.Service;
using IpBan.Agent.Service.impl;
using IpBan.Shared.Models;
using IpBan.Shared.Serialization;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace IpBan.Agent.Tests;

public sealed class ManualUnbanTests
{
    private const string Source = "192.0.2.73";

    [Fact]
    public async Task PermanentManualBanSurvivesOlderExpiryAndCanBeReleased()
    {
        var fixture = await Fixture.CreateAsync();
        using var coordinator = fixture.Coordinator;
        var connections = new ConnectionProbe();
        using var server = fixture.CreateServer(connections);
        using var stopping = new CancellationTokenSource();
        var old = await coordinator.BanAsync(fixture.Original, Source, "ban", stopping.Token);

        var result = await server.BanAsync(new AgentIpcRequest(AgentIpcOperations.Ban, Source,
            ManualBanDuration.Permanent, DisconnectExisting: true), stopping.Token);

        Assert.True(result.Success);
        Assert.Equal(ManualBanDuration.Permanent, result.BanResult!.DurationSeconds);
        Assert.Equal(FirewallActionStatus.Applied, result.BanResult.FirewallAction.ActionStatus);
        Assert.Equal(1, connections.Queries);
        Assert.Null(await coordinator.ExpireAsync(fixture.Original, Source, old.Id, "unban", stopping.Token));
        Assert.Equal(0, fixture.Original.UnbanCalls);

        await using var connection = await fixture.Factory.OpenConnectionAsync(stopping.Token);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT MAX(id) FROM firewall_actions WHERE action='ban' AND status='Applied';";
        var active = Assert.IsType<long>(await command.ExecuteScalarAsync(stopping.Token));
        Assert.True(active > old.Id);
        Assert.True((await coordinator.UnbanAsync(active, Source, stopping.Token)).Success);
        Assert.Equal(1, fixture.Original.UnbanCalls);
    }

    [Fact]
    public async Task FiniteManualBanStillExpiresAndOmittedDurationUsesDefault()
    {
        var fixture = await Fixture.CreateAsync();
        using var coordinator = fixture.Coordinator;
        using var server = fixture.CreateServer(new ConnectionProbe());
        using var stopping = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var result = await server.BanAsync(new AgentIpcRequest(AgentIpcOperations.Ban, Source, 1), stopping.Token);
        Assert.True(result.Success);
        Assert.Equal(1, result.BanResult!.DurationSeconds);
        await fixture.Original.FirstUnban.Task.WaitAsync(stopping.Token);

        var byDefault = await server.BanAsync(new AgentIpcRequest(AgentIpcOperations.Ban, "192.0.2.74"), stopping.Token);
        Assert.True(byDefault.Success);
        Assert.Equal(180, byDefault.BanResult!.DurationSeconds);
        await stopping.CancelAsync();
    }

    [Theory]
    [InlineData("192.0.2.73", 0, "INVALID_DURATION")]
    [InlineData("192.0.2.73", 604801, "INVALID_DURATION")]
    [InlineData("0.0.0.0/0", -1, "INVALID_SOURCE_ADDRESS")]
    [InlineData("::/0", -1, "INVALID_SOURCE_ADDRESS")]
    [InlineData("0.0.0.0", -1, "INVALID_SOURCE_ADDRESS")]
    [InlineData("::", -1, "INVALID_SOURCE_ADDRESS")]
    public async Task ManualBanRejectsInvalidDurationAndPermanentCatchAll(string source, int duration, string code)
    {
        var fixture = await Fixture.CreateAsync();
        using var coordinator = fixture.Coordinator;
        using var server = fixture.CreateServer(new ConnectionProbe());

        var result = await server.BanAsync(new AgentIpcRequest(AgentIpcOperations.Ban, source, duration), CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(code, result.Code);
        Assert.Equal(0, fixture.Original.BanCalls);
    }

    [Fact]
    public async Task ManualReleaseUsesOriginalProviderAndRejectsDoubleClick()
    {
        var fixture = await Fixture.CreateAsync();
        using var coordinator = fixture.Coordinator;
        var ban = await coordinator.BanAsync(fixture.Original, Source, "auto-ban", CancellationToken.None);
        var released = await coordinator.UnbanAsync(ban.Id, Source, CancellationToken.None);
        Assert.True(released.Success);
        Assert.Equal(FirewallActionStatus.Removed, released.Data!.ActionStatus);
        Assert.Equal(1, fixture.Original.UnbanCalls);
        Assert.Equal(0, fixture.Alternative.UnbanCalls);
        var duplicate = await coordinator.UnbanAsync(ban.Id, Source, CancellationToken.None);
        Assert.Equal("BAN_NOT_CURRENT", duplicate.Code);
        Assert.Equal(1, fixture.Original.UnbanCalls);
    }

    [Fact]
    public async Task OldExpiryAndOldPageCannotReleaseNewBan()
    {
        var fixture = await Fixture.CreateAsync();
        using var coordinator = fixture.Coordinator;
        var first = await coordinator.BanAsync(fixture.Original, Source, "auto-ban", CancellationToken.None);
        Assert.True((await coordinator.UnbanAsync(first.Id, Source, CancellationToken.None)).Success);
        var second = await coordinator.BanAsync(fixture.Original, Source, "auto-ban", CancellationToken.None);
        Assert.Null(await coordinator.ExpireAsync(fixture.Original, Source, first.Id, "auto-unban", CancellationToken.None));
        Assert.Equal("BAN_NOT_CURRENT", (await coordinator.UnbanAsync(first.Id, Source, CancellationToken.None)).Code);
        Assert.Equal(1, fixture.Original.UnbanCalls);
        Assert.NotNull(await coordinator.ExpireAsync(fixture.Original, Source, second.Id, "auto-unban", CancellationToken.None));
        Assert.Equal(2, fixture.Original.UnbanCalls);
    }

    [Fact]
    public async Task FailedRemovalRemainsRetryableAndReleasedMonitorCannotDisconnect()
    {
        var fixture = await Fixture.CreateAsync();
        using var coordinator = fixture.Coordinator;
        var ban = await coordinator.BanAsync(fixture.Original, Source, "ban", CancellationToken.None);
        fixture.Original.FailUnban = true;
        Assert.Equal("FIREWALL_UNBAN_FAILED", (await coordinator.UnbanAsync(ban.Id, Source, CancellationToken.None)).Code);
        fixture.Original.FailUnban = false;
        Assert.True((await coordinator.UnbanAsync(ban.Id, Source, CancellationToken.None)).Success);
        var disconnected = false;
        Assert.False(await coordinator.WhileCurrentAsync(Source, ban.Id, () =>
        {
            disconnected = true;
            return Task.CompletedTask;
        }, CancellationToken.None));
        Assert.False(disconnected);
    }

    [Fact]
    public async Task WrongSourceAndStaleFailureSnapshotCannotChangeFirewall()
    {
        var fixture = await Fixture.CreateAsync();
        using var coordinator = fixture.Coordinator;
        var evidenceTime = DateTimeOffset.UtcNow.AddSeconds(-10);
        var first = await coordinator.BanAsync(fixture.Original, Source, "auto-ban", CancellationToken.None);
        Assert.Equal("BAN_NOT_CURRENT", (await coordinator.UnbanAsync(first.Id, "192.0.2.74", CancellationToken.None)).Code);
        Assert.Equal("INVALID_BAN_ACTION", (await coordinator.UnbanAsync(first.Id, "invalid", CancellationToken.None)).Code);
        Assert.Equal(0, fixture.Original.UnbanCalls);
        Assert.True((await coordinator.UnbanAsync(first.Id, Source, CancellationToken.None)).Success);
        var stale = await coordinator.BanAsync(fixture.Original, Source, "auto-ban", CancellationToken.None, evidenceTime);
        Assert.Equal("POLICY_SNAPSHOT_EXPIRED", stale.Result.ErrorCode);
        Assert.Equal(1, fixture.Original.BanCalls);
    }

    [Theory]
    [InlineData("ban")]
    [InlineData("auto-ban")]
    public async Task ConcurrentAutomaticDecisionsDoNotDuplicateActiveBanAndManualReleaseAllowsNewGeneration(string initialAction)
    {
        var fixture = await Fixture.CreateAsync();
        using var coordinator = fixture.Coordinator;
        var first = await coordinator.BanAsync(fixture.Original, Source, initialAction, CancellationToken.None);

        // 即使多个策略同时达到阈值，锁内也必须看到已生效动作，不能叠加同名防火墙规则。
        await Task.WhenAll(Enumerable.Range(0, 5).Select(_ =>
            coordinator.BanAsync(fixture.Original, Source, "auto-ban", CancellationToken.None)));
        Assert.Equal(1, fixture.Original.BanCalls);
        await using (var connection = await fixture.Factory.OpenConnectionAsync())
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT COUNT(*) FROM firewall_actions;";
            Assert.Equal(1L, (long)(await command.ExecuteScalarAsync())!);
        }

        Assert.True((await coordinator.UnbanAsync(first.Id, Source, CancellationToken.None)).Success);
        var next = await coordinator.BanAsync(fixture.Original, Source, "auto-ban", CancellationToken.None);
        Assert.Equal(2, fixture.Original.BanCalls);
        Assert.NotEqual(first.Id, next.Id);
        Assert.Null(await coordinator.ExpireAsync(fixture.Original, Source, first.Id, "auto-unban", CancellationToken.None));
        Assert.Equal(1, fixture.Original.UnbanCalls);
    }

    [Fact]
    public async Task ExpiredAutomaticBanStillRejectsItsPreviouslyHandledEvidenceSnapshot()
    {
        var fixture = await Fixture.CreateAsync();
        using var coordinator = fixture.Coordinator;
        var evidenceThrough = DateTimeOffset.UtcNow.AddSeconds(-10);
        var first = await coordinator.BanAsync(fixture.Original, Source, "auto-ban", CancellationToken.None,
            evidenceThrough);
        Assert.Equal(FirewallActionStatus.Removed,
            (await coordinator.ExpireAsync(fixture.Original, Source, first.Id, "auto-unban", CancellationToken.None))!.ActionStatus);

        // 另一个评估在到期前读到旧窗口、到期后才获锁，也不能重新消费这批已处置证据。
        var delayed = await coordinator.BanAsync(fixture.Original, Source, "auto-ban", CancellationToken.None,
            evidenceThrough);
        Assert.Equal("POLICY_SNAPSHOT_EXPIRED", delayed.Result.ErrorCode);
        Assert.Equal(1, fixture.Original.BanCalls);
        Assert.Equal(1, fixture.Original.UnbanCalls);
    }

    [Fact]
    public void ActionIdRoundTripsBeyondJavascriptIntegerPrecision()
    {
        const long id = 9007199254740993;
        var row = new FirewallActionContract(id, DateTimeOffset.UtcNow, Source, "ban", "Applied", "nftables", null, null, null, true, "Applied");
        var json = JsonSerializer.Serialize(ApiResult<FirewallActionContract[]>.Ok([row]), IpBanJsonContext.Default.ApiResultFirewallActionContractArray);
        Assert.Contains("\"id\":\"9007199254740993\"", json, StringComparison.Ordinal);
        var restored = JsonSerializer.Deserialize(json, IpBanJsonContext.Default.ApiResultFirewallActionContractArray);
        Assert.Equal(id, Assert.Single(restored!.Data!).Id);
    }

    private sealed record Fixture(FirewallActionCoordinator Coordinator, TestProvider Original, TestProvider Alternative,
        SqliteConnectionFactory Factory, TestEnvironment Environment)
    {
        public UnixDomainSocketAgentServer CreateServer(ConnectionProbe connections) => new(connections, connections,
            new SqliteLoginEventStore(Factory), new SqliteFirewallActionStore(Factory), Coordinator,
            new FirewallProviderSelector([Original]), Environment, Microsoft.Extensions.Options.Options.Create(new AgentIpcOptions()),
            NullLogger<UnixDomainSocketAgentServer>.Instance);

        public static async Task<Fixture> CreateAsync()
        {
            var directory = Path.Combine(Path.GetTempPath(), "ipban-unban-tests", Guid.NewGuid().ToString("N"));
            var options = Microsoft.Extensions.Options.Options.Create(new AgentOptions { DataDirectory = directory, DatabaseFileName = "test.sqlite3" });
            var environment = new TestEnvironment(directory);
            await new SqliteDatabaseInitializer(options, environment).InitializeAsync();
            var factory = new SqliteConnectionFactory(options, environment);
            var original = new TestProvider("nftables");
            var alternative = new TestProvider("firewalld");
            return new Fixture(new FirewallActionCoordinator(factory, new SqliteFirewallActionStore(factory), [alternative, original]),
                original, alternative, factory, environment);
        }
    }

    private sealed class TestProvider(string name) : IFirewallProvider
    {
        public string Name => name;
        public string Platform => OperatingSystem.IsWindows() ? "windows" : "linux";
        public int BanCalls { get; private set; }
        public int UnbanCalls { get; private set; }
        public bool FailUnban { get; set; }
        public TaskCompletionSource FirstUnban { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public FirewallCapabilities Capabilities => new(Name, Platform, true, true, true, false, false);
        public Task<FirewallObservation> DetectAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(new FirewallObservation(Name, FirewallStatus.Enabled, true, null, DateTimeOffset.UtcNow, Capabilities));
        public Task<FirewallActionResult> BanAsync(string sourceAddress, CancellationToken cancellationToken = default)
        {
            BanCalls++;
            return Task.FromResult(new FirewallActionResult(Name, sourceAddress, FirewallActionStatus.Applied, FirewallStatus.Enabled, null, null, DateTimeOffset.UtcNow));
        }
        public Task<FirewallActionResult> UnbanAsync(string sourceAddress, CancellationToken cancellationToken = default)
        {
            UnbanCalls++;
            FirstUnban.TrySetResult();
            return Task.FromResult(new FirewallActionResult(Name, sourceAddress, FailUnban ? FirewallActionStatus.Failed : FirewallActionStatus.Removed,
                FirewallStatus.Enabled, null, null, DateTimeOffset.UtcNow));
        }
    }

    private sealed class ConnectionProbe : IConnectionSnapshotProvider, IConnectionTerminator
    {
        public int Queries { get; private set; }

        public Task<IReadOnlyList<ConnectionSnapshotContract>> QueryAsync(CancellationToken cancellationToken = default)
        {
            Queries++;
            return Task.FromResult<IReadOnlyList<ConnectionSnapshotContract>>([]);
        }

        public Task<ConnectionTerminationResult> TerminateAsync(IReadOnlyList<ConnectionSnapshotContract> connections,
            CancellationToken cancellationToken = default) => Task.FromResult(new ConnectionTerminationResult(true, 0, 0, null));

        public Task<ConnectionTerminationResult> TerminateExplicitAsync(IReadOnlyList<ConnectionSnapshotContract> connections,
            CancellationToken cancellationToken = default) => TerminateAsync(connections, cancellationToken);
    }

    private sealed class TestEnvironment(string directory) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Test";
        public string ApplicationName { get; set; } = "IpBan.Agent.Tests";
        public string ContentRootPath { get; set; } = directory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
