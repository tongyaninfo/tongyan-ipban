using IpBan.Agent.Service;
using IpBan.Agent.Workers;
using IpBan.Shared.Models;
using IpBan.Shared.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace IpBan.Agent.Tests;

public sealed class LoginEventCollectionRetryTests
{
    [Fact]
    public async Task PartialBatchRetriesFromLastSuccessfulWatermarkWithoutDoubleCounting()
    {
        await using var fixture = await AuthenticationTestFixture.CreateAsync();
        var collector = new WatermarkCollector();
        var store = new FailSecondWriteOnceStore(fixture.Store);
        using var worker = new LoginEventCollectionHostedService(
            [collector], store, fixture.Ids, new AuthenticationTestFixture.EmptyConnections(),
            NullLogger<LoginEventCollectionHostedService>.Instance);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            await store.Complete.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var saved = await fixture.Store.QueryRecentAsync();
            Assert.Equal(5, saved.Count);
            Assert.Equal(5, saved.Select(item => item.RawEventId).Distinct().Count());
            Assert.Equal(6, store.Attempts);
            Assert.True(collector.Polls >= 2);
            await fixture.EvaluateAsync();
            Assert.Equal(1, fixture.Firewall.BanCalls);
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task ReplayedVncEvidenceRetriesAfterPersistenceFailure()
    {
        var store = new RetryStore();
        using var worker = new LoginEventCollectionHostedService(
            [new ReplayingCollector()], store, new SequentialIds(), new EmptyConnections(),
            NullLogger<LoginEventCollectionHostedService>.Instance);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            var saved = await store.Saved.Task.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Equal(2, store.Attempts);
            Assert.Equal(ProtocolKind.Vnc, saved.Protocol);
            Assert.Equal("vnc-failure-1", saved.RawEventId);
            Assert.Equal("192.0.2.10", saved.RemoteIp);
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
        }
    }

    private sealed class ReplayingCollector : ILoginEventCollector
    {
        private readonly RawLoginEventInput evidence = new(
            DateTimeOffset.UtcNow, ProtocolKind.Vnc, false, null, "192.0.2.10", 41001,
            "192.0.2.20", 5901, 42, "Xvnc", null, null, "test-vnc", "vnc-failure-1", "synthetic",
            RemoteIpAvailability: FieldAvailability.Available);

        public string Name => "test-vnc";
        public ProtocolKind Protocol => ProtocolKind.Vnc;

        public Task<IReadOnlyList<RawLoginEventInput>> CollectAsync(
            DateTimeOffset sinceUtc, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<RawLoginEventInput>>([evidence]);
    }

    private sealed class RetryStore : ILoginEventStore
    {
        public int Attempts { get; private set; }
        public TaskCompletionSource<LoginEventContract> Saved { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task AppendAsync(LoginEventContract loginEvent, CancellationToken cancellationToken = default)
        {
            Attempts++;
            if (Attempts == 1)
            {
                throw new IOException("Synthetic temporary write failure");
            }

            Saved.TrySetResult(loginEvent);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<LoginEventContract>> QueryRecentAsync(
            int limit = 100, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<LoginEventContract>>([]);
    }

    private sealed class WatermarkCollector : ILoginEventCollector
    {
        private readonly RawLoginEventInput[] evidence = Enumerable.Range(1, 5)
            .Select(attempt => AuthenticationTestFixture.Evidence(ProtocolKind.OpenSsh, attempt,
                DateTimeOffset.UtcNow.AddSeconds(-1))).ToArray();

        public string Name => "watermark-authentication";
        public ProtocolKind Protocol => ProtocolKind.OpenSsh;
        public int Polls { get; private set; }

        public Task<IReadOnlyList<RawLoginEventInput>> CollectAsync(DateTimeOffset sinceUtc,
            CancellationToken cancellationToken = default)
        {
            Polls++;
            // 与原生日志查询一致：只返回水位后的证据，不能靠测试桩无限重放掩盖水位错误。
            return Task.FromResult<IReadOnlyList<RawLoginEventInput>>(evidence.Where(item => item.OccurredAtUtc >= sinceUtc).ToArray());
        }
    }

    private sealed class FailSecondWriteOnceStore(ILoginEventStore inner) : ILoginEventStore
    {
        public int Attempts { get; private set; }
        public TaskCompletionSource Complete { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task AppendAsync(LoginEventContract loginEvent, CancellationToken cancellationToken = default)
        {
            Attempts++;
            if (Attempts == 2)
            {
                throw new IOException("Synthetic second-row temporary persistence failure");
            }
            await inner.AppendAsync(loginEvent, cancellationToken);
            if ((await inner.QueryRecentAsync(cancellationToken: cancellationToken)).Count == 5)
            {
                Complete.TrySetResult();
            }
        }

        public Task<IReadOnlyList<LoginEventContract>> QueryRecentAsync(int limit = 100,
            CancellationToken cancellationToken = default) => inner.QueryRecentAsync(limit, cancellationToken);
    }

    private sealed class SequentialIds : IIdService
    {
        private long current;
        public long NewId => Interlocked.Increment(ref current);
    }

    private sealed class EmptyConnections : IConnectionSnapshotProvider
    {
        public Task<IReadOnlyList<ConnectionSnapshotContract>> QueryAsync(
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<ConnectionSnapshotContract>>([]);
    }
}
