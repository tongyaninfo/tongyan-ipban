using IpBan.Engine.Models;

namespace IpBan.Engine.Services;

/// <summary>
/// 纯函数封禁判定骨架。它只处理已归一化的输入，不读取数据库、不访问系统命令。
/// </summary>
public static class BanDecisionEvaluator
{
    public static BanDecision Evaluate(DecisionInput input)
    {
        ArgumentNullException.ThrowIfNull(input);

        if (input.IsWhitelisted)
        {
            return Create(input, DecisionAction.Allow, null, "命中白名单");
        }

        if (input.IsBlacklisted)
        {
            return Create(input, DecisionAction.Ban, GetExpiry(input), "命中黑名单");
        }

        if (!input.Policy.Enabled)
        {
            return Create(input, DecisionAction.Allow, null, "策略未启用");
        }

        if (input.FailureCountInWindow < input.Policy.FailureThreshold)
        {
            return Create(input, DecisionAction.Observe, null, "未达到封禁阈值");
        }

        return Create(input, DecisionAction.Ban, GetExpiry(input), "达到封禁阈值");
    }

    // 判定器使用归一化后的零时长表示永久封禁，到期时间为空，可由管理员解封。
    private static DateTimeOffset? GetExpiry(DecisionInput input) => input.Policy.BanDuration == TimeSpan.Zero
        ? null
        : input.EvaluatedAtUtc + input.Policy.BanDuration;

    private static BanDecision Create(
        DecisionInput input,
        DecisionAction action,
        DateTimeOffset? expiresAtUtc,
        string reason) => new(
        action,
        input.SourceIp,
        input.Protocol,
        input.Policy.Version,
        input.FailureCountInWindow,
        input.EvaluatedAtUtc,
        expiresAtUtc,
        reason);
}
