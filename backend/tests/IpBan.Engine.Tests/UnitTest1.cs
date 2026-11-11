using System.Globalization;
using IpBan.Engine.Models;
using IpBan.Engine.Services;
using IpBan.Shared.Models;

namespace IpBan.Engine.Tests;

public sealed class BanDecisionEvaluatorTests
{
    [Fact]
    public void WhitelistTakesPrecedenceOverThreshold()
    {
        var input = CreateInput(isWhitelisted: true, failureCount: 99);

        var decision = BanDecisionEvaluator.Evaluate(input);

        Assert.Equal(DecisionAction.Allow, decision.Action);
        Assert.Equal("命中白名单", decision.Reason);
    }

    [Fact]
    public void ThresholdProducesBanWithExpiry()
    {
        var now = DateTimeOffset.Parse("2026-01-01T00:00:00Z", CultureInfo.InvariantCulture);
        var input = CreateInput(failureCount: 5, evaluatedAtUtc: now);

        var decision = BanDecisionEvaluator.Evaluate(input);

        Assert.Equal(DecisionAction.Ban, decision.Action);
        Assert.Equal(now.AddHours(1), decision.ExpiresAtUtc);
    }

    [Fact]
    public void BelowThresholdRemainsObservable()
    {
        var input = CreateInput(failureCount: 4);

        var decision = BanDecisionEvaluator.Evaluate(input);

        Assert.Equal(DecisionAction.Observe, decision.Action);
        Assert.Null(decision.ExpiresAtUtc);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void IndefiniteBanHasNoExpiry(bool isBlacklisted)
    {
        var input = CreateInput(failureCount: 5);
        input = input with { IsBlacklisted = isBlacklisted, Policy = input.Policy with { BanDuration = TimeSpan.Zero } };

        var decision = BanDecisionEvaluator.Evaluate(input);

        Assert.Equal(DecisionAction.Ban, decision.Action);
        Assert.Null(decision.ExpiresAtUtc);
    }

    [Fact]
    public void LargestFiniteDurationStillHasAnExpiry()
    {
        var input = CreateInput(failureCount: 5);
        input = input with { Policy = input.Policy with { BanDuration = TimeSpan.FromSeconds(int.MaxValue) } };

        var decision = BanDecisionEvaluator.Evaluate(input);

        Assert.Equal(input.EvaluatedAtUtc.AddSeconds(int.MaxValue), decision.ExpiresAtUtc);
    }

    private static DecisionInput CreateInput(
        bool isWhitelisted = false,
        int failureCount = 0,
        DateTimeOffset? evaluatedAtUtc = null) => new(
        SourceIp: "192.0.2.10",
        Protocol: ProtocolKind.Ssh,
        FailureCountInWindow: failureCount,
        IsWhitelisted: isWhitelisted,
        IsBlacklisted: false,
        Policy: new BanPolicySnapshot(
            Version: 1,
            FailureThreshold: 5,
            Window: TimeSpan.FromMinutes(5),
            BanDuration: TimeSpan.FromHours(1),
            Enabled: true),
        EvaluatedAtUtc: evaluatedAtUtc ?? DateTimeOffset.UtcNow);
}
