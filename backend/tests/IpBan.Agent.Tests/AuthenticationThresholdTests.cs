using IpBan.Agent.Options;
using IpBan.Agent.Service;
using IpBan.Agent.Service.impl;
using IpBan.Agent.Workers;
using IpBan.Engine.Services;
using IpBan.Shared.Models;
using IpBan.Shared.Service;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;

namespace IpBan.Agent.Tests;

public sealed class AuthenticationThresholdTests
{
    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(int.MaxValue)]
    public async Task IndefiniteAndLongFiniteBansRequireThresholdAndCanBeManuallyReleased(int durationSeconds)
    {
        await using var fixture = await AuthenticationTestFixture.CreateAsync();
        await fixture.SetBanDurationAsync(durationSeconds);
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            await fixture.PersistAsync(AuthenticationTestFixture.Evidence(ProtocolKind.Ssh, attempt,
                DateTimeOffset.UtcNow));
            await fixture.EvaluateAsync();
            Assert.Equal(attempt < 5 ? 0 : 1, fixture.Firewall.BanCalls);
        }

        // 永久封禁和旧版的 0 均无到期任务，长时长也不能立即解除。
        await Task.Delay(100);
        Assert.Equal(1L, await fixture.CountFirewallActionsAsync());
        Assert.True((await fixture.ManuallyReleaseCurrentAsync()).Success);
        await fixture.EvaluateAsync();
        Assert.Equal(1, fixture.Firewall.BanCalls);
        Assert.Equal(2L, await fixture.CountFirewallActionsAsync());
    }

    [Fact]
    public async Task ZeroDurationObservationPolicyDoesNotBanAtThreshold()
    {
        await using var fixture = await AuthenticationTestFixture.CreateAsync();
        await fixture.SetBanDurationAsync(0, action: "Observe");
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            await fixture.PersistAsync(AuthenticationTestFixture.Evidence(ProtocolKind.Ssh, attempt,
                DateTimeOffset.UtcNow));
        }

        await fixture.EvaluateAsync();

        Assert.Equal(0, fixture.Firewall.BanCalls);
        Assert.Equal(0L, await fixture.CountFirewallActionsAsync());
    }

    [Fact]
    public async Task FiniteDurationStillAutomaticallyExpires()
    {
        await using var fixture = await AuthenticationTestFixture.CreateAsync();
        await fixture.SetBanDurationAsync(1);
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            await fixture.PersistAsync(AuthenticationTestFixture.Evidence(ProtocolKind.Ssh, attempt,
                DateTimeOffset.UtcNow));
        }
        await fixture.EvaluateAsync();
        var deadline = DateTimeOffset.UtcNow.AddSeconds(5);
        while (await fixture.CountFirewallActionsAsync() < 2 && DateTimeOffset.UtcNow < deadline)
            await Task.Delay(25);

        Assert.Equal(2L, await fixture.CountFirewallActionsAsync());
        Assert.False((await fixture.ManuallyReleaseCurrentAsync()).Success);
        Assert.Equal(1, fixture.Firewall.BanCalls);
    }

    [Theory]
    [InlineData(ProtocolKind.Ssh, false)]
    [InlineData(ProtocolKind.OpenSsh, false)]
    [InlineData(ProtocolKind.Rdp, false)]
    [InlineData(ProtocolKind.WinRm, false)]
    [InlineData(ProtocolKind.Vnc, false)]
    [InlineData(ProtocolKind.Ssh, true)]
    [InlineData(ProtocolKind.OpenSsh, true)]
    public async Task EachEvaluationKeepsFirstFourOpenAndBansOnlyAfterFifth(
        ProtocolKind protocol, bool reuseConnection)
    {
        await using var fixture = await AuthenticationTestFixture.CreateAsync();
        var occurred = DateTimeOffset.UtcNow.AddSeconds(-10);
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            // 相同 TCP 连接可以提交多个密码；独立认证不能按端点或短时间窗口合并。
            var raw = AuthenticationTestFixture.Evidence(protocol, attempt, occurred.AddMilliseconds(attempt),
                remotePort: reuseConnection ? 41000 : 41000 + attempt);
            await fixture.PersistAsync(raw);
            await fixture.EvaluateAsync();
            Assert.Equal(attempt < 5 ? 0 : 1, fixture.Firewall.BanCalls);
            Assert.Equal(attempt, (await fixture.Store.QueryRecentAsync()).Count);
        }

        Assert.Equal(1L, await fixture.CountAppliedBansAsync());
    }

    [Theory]
    [InlineData(ProtocolKind.Ssh)]
    [InlineData(ProtocolKind.Unidentified)]
    public async Task UnidentifiedWindowsFailuresMatchAllButNotSshPolicy(ProtocolKind storedProtocol)
    {
        await using var fixture = await AuthenticationTestFixture.CreateAsync();
        var occurred = DateTimeOffset.UtcNow.AddSeconds(-10);
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            var raw = AuthenticationTestFixture.Evidence(storedProtocol, attempt, occurred.AddMilliseconds(attempt)) with
            {
                Collector = "windows-eventlog:Security",
                EvidenceSource = "eventlog:Security:4625",
                LocalProcessName = @"C:\Windows\System32\services.exe"
            };
            await fixture.PersistAsync(raw);
        }

        var recent = await fixture.Store.QueryRecentAsync();
        Assert.Equal(5, recent.Count);
        Assert.All(recent, loginEvent => Assert.Equal(ProtocolKind.Unidentified, loginEvent.Protocol));

        await fixture.SetProtocolAsync("Ssh");
        await fixture.EvaluateAsync();
        Assert.Equal(0, fixture.Firewall.BanCalls);

        await fixture.SetProtocolAsync("ALL");
        await fixture.EvaluateAsync();
        Assert.Equal(1, fixture.Firewall.BanCalls);
    }

    [Fact]
    public async Task SuccessfulRetryDoesNotEraseThePreviousFailedAuthentication()
    {
        await using var fixture = await AuthenticationTestFixture.CreateAsync();
        var occurred = DateTimeOffset.UtcNow.AddSeconds(-10);
        await fixture.PersistAsync(AuthenticationTestFixture.Evidence(ProtocolKind.OpenSsh, 1, occurred));
        await fixture.PersistAsync(AuthenticationTestFixture.Evidence(ProtocolKind.OpenSsh, 101,
            occurred.AddSeconds(1), success: true));
        for (var attempt = 2; attempt <= 4; attempt++)
        {
            await fixture.PersistAsync(AuthenticationTestFixture.Evidence(ProtocolKind.OpenSsh, attempt,
                occurred.AddSeconds(attempt), remotePort: 41000 + attempt));
        }

        await fixture.EvaluateAsync();
        Assert.Equal(0, fixture.Firewall.BanCalls);
        await fixture.PersistAsync(AuthenticationTestFixture.Evidence(ProtocolKind.OpenSsh, 5,
            occurred.AddSeconds(5), remotePort: 41005));
        await fixture.EvaluateAsync();

        Assert.Equal(1, fixture.Firewall.BanCalls);
        var saved = await fixture.Store.QueryRecentAsync();
        Assert.Equal(5, saved.Count(item => !item.Success));
        Assert.Single(saved, item => item.Success);
    }

    [Fact]
    public async Task ReplayingEvidenceAcrossStoreInstancesCannotReachThresholdEarly()
    {
        await using var fixture = await AuthenticationTestFixture.CreateAsync();
        var occurred = DateTimeOffset.UtcNow.AddSeconds(-10);
        var evidence = Enumerable.Range(1, 4)
            .Select(attempt => AuthenticationTestFixture.Evidence(ProtocolKind.Ssh, attempt,
                occurred.AddMilliseconds(attempt))).ToArray();
        foreach (var item in evidence)
        {
            await fixture.PersistAsync(item);
        }

        // 新仓储实例模拟 Agent 重启后丢失内存 seen 集合，持久化必须仍保证同证据只写一条。
        var restartedStore = new SqliteLoginEventStore(fixture.Factory);
        foreach (var item in evidence.Concat(evidence))
        {
            await restartedStore.AppendAsync(LoginEventNormalizer.Normalize(fixture.Ids.NewId, item));
        }
        await fixture.EvaluateAsync();
        Assert.Equal(4, (await fixture.Store.QueryRecentAsync()).Count);
        Assert.Equal(0, fixture.Firewall.BanCalls);

        await fixture.PersistAsync(AuthenticationTestFixture.Evidence(ProtocolKind.Ssh, 5,
            occurred.AddMilliseconds(5)));
        await fixture.EvaluateAsync();
        Assert.Equal(1, fixture.Firewall.BanCalls);
        Assert.Equal(5, (await fixture.Store.QueryRecentAsync()).Count);
    }

    [Fact]
    public async Task HandledFailuresCannotRebanAfterCooldownOrExpiryAndNextBanNeedsFiveNewFailures()
    {
        await using var fixture = await AuthenticationTestFixture.CreateAsync();
        var occurred = DateTimeOffset.UtcNow.AddSeconds(-10);
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            await fixture.PersistAsync(AuthenticationTestFixture.Evidence(ProtocolKind.Ssh, attempt,
                occurred.AddMilliseconds(attempt)));
        }
        await fixture.EvaluateAsync();
        Assert.Equal(1, fixture.Firewall.BanCalls);

        await fixture.SetCooldownAsync(0);
        // 实现的冷却下限为1秒；等待其结束，避免只因冷却而掩盖旧证据重新触发的问题。
        await Task.Delay(TimeSpan.FromMilliseconds(1100));
        await fixture.EvaluateAsync();
        Assert.Equal(1, fixture.Firewall.BanCalls);
        Assert.Equal(1L, await fixture.CountAppliedBansAsync());

        Assert.Equal(FirewallActionStatus.Removed, (await fixture.ExpireCurrentAsync())!.ActionStatus);
        await fixture.EvaluateAsync();
        Assert.Equal(1, fixture.Firewall.BanCalls);

        // 自动到期不等于重新消费同一批失败；需要解封后再产生完整的五次新失败。
        for (var attempt = 6; attempt <= 10; attempt++)
        {
            await fixture.PersistAsync(AuthenticationTestFixture.Evidence(ProtocolKind.Ssh, attempt,
                DateTimeOffset.UtcNow));
            await fixture.EvaluateAsync();
            Assert.Equal(attempt < 10 ? 1 : 2, fixture.Firewall.BanCalls);
        }
        Assert.Equal(2L, await fixture.CountAppliedBansAsync());

    }

    [Fact]
    public async Task AdditionalFailuresWhileBanIsActiveCannotCreateDuplicateFirewallRule()
    {
        await using var fixture = await AuthenticationTestFixture.CreateAsync();
        var occurred = DateTimeOffset.UtcNow.AddSeconds(-10);
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            await fixture.PersistAsync(AuthenticationTestFixture.Evidence(ProtocolKind.OpenSsh, attempt,
                occurred.AddMilliseconds(attempt)));
        }
        await fixture.EvaluateAsync();
        await fixture.SetCooldownAsync(0);
        await Task.Delay(TimeSpan.FromMilliseconds(1100));

        // 模拟已在途或延迟送达的新认证结果，不允许给当前有效封禁叠加同名规则。
        for (var attempt = 6; attempt <= 10; attempt++)
        {
            await fixture.PersistAsync(AuthenticationTestFixture.Evidence(ProtocolKind.OpenSsh, attempt,
                DateTimeOffset.UtcNow));
            await fixture.EvaluateAsync();
            Assert.Equal(1, fixture.Firewall.BanCalls);
        }
        Assert.Equal(1L, await fixture.CountAppliedBansAsync());
        Assert.Equal(1L, await fixture.CountFirewallActionsAsync());
    }

    [Theory]
    [InlineData("auto-ban", false, 1)]
    [InlineData("auto-ban", true, 0)]
    [InlineData("auto-ban", null, 0)]
    [InlineData("ban", false, 1)]
    public async Task NewThresholdCanReplacePriorNftablesBanOnlyWhenRuleIsConfirmedMissing(
        string priorAction, bool? rulePresent, int expectedRuleAdds)
    {
        var runner = new NftablesRuleRunner(rulePresent);
        var provider = new NftablesFirewallProvider(runner);
        await using var fixture = await AuthenticationTestFixture.CreateAsync(provider);
        await fixture.SetCooldownAsync(0);
        var reference = DateTimeOffset.UtcNow.AddMinutes(-1);
        await new SqliteFirewallActionStore(fixture.Factory).AppendAsync(priorAction, new FirewallActionResult(
            provider.Name, "192.0.2.10", FirewallActionStatus.Applied, FirewallStatus.Enabled, null, null, reference));

        // 旧证据仍在窗口内。没有新的完整阈值批次时，即使规则已丢失也不能重新下发。
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            await fixture.PersistAsync(AuthenticationTestFixture.Evidence(ProtocolKind.Ssh, attempt,
                reference.AddSeconds(-attempt)));
        }
        for (var attempt = 6; attempt <= 9; attempt++)
        {
            await fixture.PersistAsync(AuthenticationTestFixture.Evidence(ProtocolKind.Ssh, attempt,
                reference.AddSeconds(attempt)));
        }
        await fixture.EvaluateAsync();
        Assert.Equal(0, runner.ChainReads);
        Assert.Equal(0, runner.RuleAdds);

        await fixture.PersistAsync(AuthenticationTestFixture.Evidence(ProtocolKind.Ssh, 10, reference.AddSeconds(10)));
        await fixture.EvaluateAsync();
        Assert.Equal(1, runner.ChainReads);
        Assert.Equal(expectedRuleAdds, runner.RuleAdds);
        Assert.Equal((priorAction == "auto-ban" ? 1L : 0L) + expectedRuleAdds,
            await fixture.CountAppliedBansAsync());

        await fixture.EvaluateAsync();
        Assert.Equal(expectedRuleAdds, runner.RuleAdds);
        Assert.Equal(1L + expectedRuleAdds, await fixture.CountFirewallActionsAsync());
    }

    [Fact]
    public async Task SuccessfulManualUnbanResetsDefaultCooldownAndRequiresFiveNewFailures()
    {
        await using var fixture = await AuthenticationTestFixture.CreateAsync();
        var occurred = DateTimeOffset.UtcNow.AddSeconds(-10);
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            await fixture.PersistAsync(AuthenticationTestFixture.Evidence(ProtocolKind.Ssh, attempt,
                occurred.AddMilliseconds(attempt)));
        }
        await fixture.EvaluateAsync();
        Assert.Equal(1, fixture.Firewall.BanCalls);
        Assert.True((await fixture.ManuallyReleaseCurrentAsync()).Success);

        // 保持默认900秒冷却：成功手动解封开始新一轮，但不能重复使用之前的五条失败。
        await fixture.EvaluateAsync();
        Assert.Equal(1, fixture.Firewall.BanCalls);
        for (var attempt = 6; attempt <= 10; attempt++)
        {
            await fixture.PersistAsync(AuthenticationTestFixture.Evidence(ProtocolKind.Ssh, attempt,
                DateTimeOffset.UtcNow, remotePort: 42000));
            await fixture.EvaluateAsync();
            Assert.Equal(attempt < 10 ? 1 : 2, fixture.Firewall.BanCalls);
        }
        Assert.Equal(2L, await fixture.CountAppliedBansAsync());

        // 旧的成功手动解封只重置它之前的封禁；新封禁的冷却不能被旧解封永久绕过。
        Assert.Equal(FirewallActionStatus.Removed, (await fixture.ExpireCurrentAsync())!.ActionStatus);
        for (var attempt = 11; attempt <= 15; attempt++)
        {
            await fixture.PersistAsync(AuthenticationTestFixture.Evidence(ProtocolKind.Ssh, attempt,
                DateTimeOffset.UtcNow, remotePort: 43000));
        }
        await fixture.EvaluateAsync();
        Assert.Equal(2, fixture.Firewall.BanCalls);
    }

    [Fact]
    public async Task FailedManualUnbanDoesNotResetDefaultCooldown()
    {
        await using var fixture = await AuthenticationTestFixture.CreateAsync();
        var occurred = DateTimeOffset.UtcNow.AddSeconds(-10);
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            await fixture.PersistAsync(AuthenticationTestFixture.Evidence(ProtocolKind.OpenSsh, attempt,
                occurred.AddMilliseconds(attempt)));
        }
        await fixture.EvaluateAsync();
        fixture.Firewall.FailUnban = true;
        Assert.False((await fixture.ManuallyReleaseCurrentAsync()).Success);
        fixture.Firewall.FailUnban = false;

        // 自动到期解除当前规则，排除active-ban保护的影响，单独验证失败的手动解封不重置冷却。
        Assert.Equal(FirewallActionStatus.Removed, (await fixture.ExpireCurrentAsync())!.ActionStatus);
        for (var attempt = 6; attempt <= 10; attempt++)
        {
            await fixture.PersistAsync(AuthenticationTestFixture.Evidence(ProtocolKind.OpenSsh, attempt,
                DateTimeOffset.UtcNow));
        }
        await fixture.EvaluateAsync();
        Assert.Equal(1, fixture.Firewall.BanCalls);
        Assert.Equal(1L, await fixture.CountAppliedBansAsync());
    }

    [Fact]
    public async Task OtherSourceManualUnbanDoesNotResetThisSourcesDefaultCooldown()
    {
        await using var fixture = await AuthenticationTestFixture.CreateAsync();
        var occurred = DateTimeOffset.UtcNow.AddSeconds(-10);
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            await fixture.PersistAsync(AuthenticationTestFixture.Evidence(ProtocolKind.Ssh, attempt,
                occurred.AddMilliseconds(attempt)));
        }
        await fixture.EvaluateAsync();
        Assert.Equal(FirewallActionStatus.Removed, (await fixture.ExpireCurrentAsync())!.ActionStatus);
        Assert.True((await fixture.CreateAndManuallyReleaseOtherSourceAsync("192.0.2.99")).Success);

        // 另一来源的成功解封不能给本来源绕过900秒冷却；两次provider调用分别属于两个来源。
        for (var attempt = 6; attempt <= 10; attempt++)
        {
            await fixture.PersistAsync(AuthenticationTestFixture.Evidence(ProtocolKind.Ssh, attempt,
                DateTimeOffset.UtcNow));
        }
        await fixture.EvaluateAsync();
        Assert.Equal(2, fixture.Firewall.BanCalls);
        Assert.Equal(1L, await fixture.CountAppliedBansAsync());
    }

    private sealed class NftablesRuleRunner(bool? rulePresent) : IFirewallCommandRunner
    {
        private const string ChainPrefix = "table inet ipban {\n chain input {\n type filter hook input priority filter; policy accept;\n";
        private const string ChainSuffix = " }\n}\n";

        public int ChainReads { get; private set; }
        public int RuleAdds { get; private set; }

        public Task<FirewallCommandResult> ExecuteAsync(FirewallCommand command, TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            Assert.Equal("nft", command.FileName);
            FirewallCommandResult result;
            switch (command.Arguments)
            {
                case ["-a", "list", "chain", "inet", "ipban", "input"]:
                    ChainReads++;
                    result = rulePresent is null
                        ? new FirewallCommandResult(1, "", "Operation not permitted", WasPermissionDenied: true)
                        : new FirewallCommandResult(0, ChainPrefix
                            + (rulePresent.Value ? " ip saddr 192.0.2.10 drop # handle 7\n" : "") + ChainSuffix, "");
                    break;
                case ["add", "rule", "inet", "ipban", "input", "ip", "saddr", "192.0.2.10", "drop"]:
                    RuleAdds++;
                    rulePresent = true;
                    result = new FirewallCommandResult(0, "", "");
                    break;
                case ["list", "ruleset"] or ["list", "table", "inet", "ipban"] or ["list", "chain", "inet", "ipban", "input"]:
                    result = new FirewallCommandResult(0, ChainPrefix + ChainSuffix, "");
                    break;
                default:
                    throw new InvalidOperationException($"Unexpected nft command: {string.Join(' ', command.Arguments)}");
            }
            return Task.FromResult(result);
        }
    }
}

/// <summary>使用隔离 SQLite 和真实判定宿主，仅以假防火墙代替宿主系统命令。</summary>
internal sealed class AuthenticationTestFixture : IAsyncDisposable
{
    private readonly CancellationTokenSource lifetime = new();
    private readonly FirewallActionCoordinator coordinator;
    private readonly AutomaticBanHostedService worker;

    private AuthenticationTestFixture(SqliteConnectionFactory factory, IFirewallProvider? provider)
    {
        Factory = factory;
        Store = new SqliteLoginEventStore(factory);
        Firewall = new RecordingFirewall();
        var activeFirewall = provider ?? Firewall;
        var actions = new SqliteFirewallActionStore(factory);
        coordinator = new FirewallActionCoordinator(factory, actions, [activeFirewall]);
        IFirewallProviderSelector selector = provider is null
            ? new FirewallProviderSelector([Firewall])
            : new FixedFirewallSelector(activeFirewall);
        worker = new AutomaticBanHostedService(factory, selector, actions,
            coordinator, new EmptyConnections(), new EmptyTerminator(),
            NullLogger<AutomaticBanHostedService>.Instance);
    }

    public SqliteConnectionFactory Factory { get; }
    public SqliteLoginEventStore Store { get; }
    public SequentialIds Ids { get; } = new();
    public RecordingFirewall Firewall { get; }

    public static async Task<AuthenticationTestFixture> CreateAsync(IFirewallProvider? provider = null)
    {
        var directory = Path.Combine(Path.GetTempPath(), "ipban-authentication-tests", Guid.NewGuid().ToString("N"));
        var options = Microsoft.Extensions.Options.Options.Create(new AgentOptions
        {
            DataDirectory = directory,
            DatabaseFileName = "test.sqlite3"
        });
        var environment = new TestEnvironment(directory);
        await new SqliteDatabaseInitializer(options, environment).InitializeAsync();
        var fixture = new AuthenticationTestFixture(new SqliteConnectionFactory(options, environment), provider);
        await using var connection = await fixture.Factory.OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE ban_policies SET enabled=CASE WHEN name='All protocol brute force' THEN 1 ELSE 0 END, threshold=5, window_seconds=300, observe_seconds=0, cooldown_seconds=900, ban_duration_seconds=1800;";
        await command.ExecuteNonQueryAsync();
        return fixture;
    }

    public static RawLoginEventInput Evidence(ProtocolKind protocol, int attempt, DateTimeOffset occurred,
        bool success = false, int remotePort = 41000) => new(
        occurred, protocol, success, "test-user", "192.0.2.10", remotePort, "192.0.2.20", 22,
        42, "test-server", null, null, "synthetic-authentication", $"attempt-{attempt}", "synthetic",
        FieldAvailability.Available, FieldAvailability.Available, FieldAvailability.Available,
        FieldAvailability.Available, FieldAvailability.Available);

    public Task PersistAsync(RawLoginEventInput raw) =>
        Store.AppendAsync(LoginEventNormalizer.Normalize(Ids.NewId, raw));

    public Task EvaluateAsync() => worker.EvaluatePoliciesAsync(lifetime.Token);

    public async Task SetProtocolAsync(string protocol)
    {
        await using var connection = await Factory.OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE ban_policies SET protocol=$protocol WHERE enabled=1;";
        command.Parameters.AddWithValue("$protocol", protocol);
        await command.ExecuteNonQueryAsync();
    }

    public async Task SetCooldownAsync(int seconds)
    {
        await using var connection = await Factory.OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE ban_policies SET cooldown_seconds=$seconds WHERE enabled=1;";
        command.Parameters.AddWithValue("$seconds", seconds);
        await command.ExecuteNonQueryAsync();
    }

    public async Task SetBanDurationAsync(int seconds, string action = "Ban")
    {
        await using var connection = await Factory.OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE ban_policies SET ban_duration_seconds=$seconds, action=$action WHERE enabled=1;";
        command.Parameters.AddWithValue("$seconds", seconds);
        command.Parameters.AddWithValue("$action", action);
        await command.ExecuteNonQueryAsync();
    }

    public async Task<FirewallActionResult?> ExpireCurrentAsync()
    {
        long id;
        await using (var connection = await Factory.OpenConnectionAsync())
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT id FROM firewall_actions WHERE action='auto-ban' AND status='Applied' ORDER BY id DESC LIMIT 1;";
            id = (long)(await command.ExecuteScalarAsync())!;
        }
        return await coordinator.ExpireAsync(Firewall, "192.0.2.10", id, "auto-unban", lifetime.Token);
    }

    public async Task<ApiResult<FirewallActionResult>> ManuallyReleaseCurrentAsync()
    {
        long id;
        await using (var connection = await Factory.OpenConnectionAsync())
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT id FROM firewall_actions WHERE source_ip='192.0.2.10' AND action='auto-ban' AND status='Applied' ORDER BY id DESC LIMIT 1;";
            id = (long)(await command.ExecuteScalarAsync())!;
        }
        return await coordinator.UnbanAsync(id, "192.0.2.10", lifetime.Token);
    }

    public async Task<ApiResult<FirewallActionResult>> CreateAndManuallyReleaseOtherSourceAsync(string source)
    {
        var ban = await coordinator.BanAsync(Firewall, source, "ban", lifetime.Token);
        return await coordinator.UnbanAsync(ban.Id, source, lifetime.Token);
    }

    public async Task<long> CountAppliedBansAsync()
    {
        await using var connection = await Factory.OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM firewall_actions WHERE action='auto-ban' AND status='Applied';";
        return (long)(await command.ExecuteScalarAsync())!;
    }

    public async Task<long> CountFirewallActionsAsync()
    {
        await using var connection = await Factory.OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM firewall_actions;";
        return (long)(await command.ExecuteScalarAsync())!;
    }

    public async ValueTask DisposeAsync()
    {
        await lifetime.CancelAsync();
        await worker.StopAsync(CancellationToken.None);
        worker.Dispose();
        coordinator.Dispose();
        lifetime.Dispose();
        // 保留本次隔离测试数据库，便于失败时回读；测试不删除任何文件。
    }

    internal sealed class SequentialIds : IIdService
    {
        private long current;
        public long NewId => Interlocked.Increment(ref current);
    }

    internal sealed class EmptyConnections : IConnectionSnapshotProvider
    {
        public Task<IReadOnlyList<ConnectionSnapshotContract>> QueryAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<ConnectionSnapshotContract>>([]);
    }

    private sealed class EmptyTerminator : IConnectionTerminator
    {
        public Task<ConnectionTerminationResult> TerminateAsync(IReadOnlyList<ConnectionSnapshotContract> connections,
            CancellationToken cancellationToken = default) => Task.FromResult(new ConnectionTerminationResult(true, 0, 0, null));
        public Task<ConnectionTerminationResult> TerminateExplicitAsync(IReadOnlyList<ConnectionSnapshotContract> connections,
            CancellationToken cancellationToken = default) => TerminateAsync(connections, cancellationToken);
    }

    private sealed class FixedFirewallSelector(IFirewallProvider provider) : IFirewallProviderSelector
    {
        public async Task<FirewallProviderSelection> SelectAsync(string platform, CancellationToken cancellationToken = default)
        {
            var observation = await provider.DetectAsync(cancellationToken);
            return new FirewallProviderSelection(provider, observation, [observation]);
        }
    }

    internal sealed class RecordingFirewall : IFirewallProvider
    {
        public string Name => "synthetic-firewall";
        public string Platform => OperatingSystem.IsWindows() ? "windows" : "linux";
        public int BanCalls { get; private set; }
        public bool FailUnban { get; set; }
        public FirewallCapabilities Capabilities => new(Name, Platform, true, true, true, false, false);
        public Task<FirewallObservation> DetectAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(new FirewallObservation(Name, FirewallStatus.Enabled, true, null, DateTimeOffset.UtcNow, Capabilities));
        public Task<FirewallActionResult> BanAsync(string sourceAddress, CancellationToken cancellationToken = default)
        {
            BanCalls++;
            return Task.FromResult(new FirewallActionResult(Name, sourceAddress, FirewallActionStatus.Applied,
                FirewallStatus.Enabled, null, null, DateTimeOffset.UtcNow));
        }
        public Task<FirewallActionResult> UnbanAsync(string sourceAddress, CancellationToken cancellationToken = default) =>
            Task.FromResult(new FirewallActionResult(Name, sourceAddress, FailUnban ? FirewallActionStatus.Failed : FirewallActionStatus.Removed,
                FirewallStatus.Enabled, null, null, DateTimeOffset.UtcNow));
    }

    private sealed class TestEnvironment(string directory) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Test";
        public string ApplicationName { get; set; } = "IpBan.Agent.Tests";
        public string ContentRootPath { get; set; } = directory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
