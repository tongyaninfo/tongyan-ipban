using System.Text.Json;
using IpBan.Shared.Models;

namespace IpBan.Api.Service;

/// <summary>策略输入按字段返回可翻译的校验码；错误数值不能变成服务不可用。</summary>
internal static class BanPolicyRequestValidator
{
    public static ApiResult<BanPolicyContract>? Validate(UpsertBanPolicyRequest? request)
    {
        if (request is null || string.IsNullOrWhiteSpace(request.Name)
            || string.IsNullOrWhiteSpace(request.Action))
            return InvalidField(null);
        if (request.Threshold < 1) return InvalidField("threshold");
        if (request.WindowSeconds < 1) return InvalidField("windowSeconds");
        if (request.ObserveSeconds < 0) return InvalidField("observeSeconds");
        if (request.CooldownSeconds < 0) return InvalidField("cooldownSeconds");
        if (request.BanDurationSeconds < -1)
            return InvalidField("banDurationSeconds");
        return null;
    }

    public static ApiResult<BanPolicyContract> InvalidJson(JsonException exception)
    {
        // 仅使用系统提供的字段路径选取固定提示，不回传原始请求或异常内容。
        var field = exception.Path is { } path && path.StartsWith("$.", StringComparison.Ordinal)
            ? path[2..]
            : null;
        return InvalidField(field);
    }

    private static ApiResult<BanPolicyContract> InvalidField(string? field) => field switch
    {
        "threshold" => ApiResult<BanPolicyContract>.Fail("INVALID_BAN_POLICY_THRESHOLD", "失败阈值必须是 1 至 2147483647 之间的整数。"),
        "windowSeconds" => ApiResult<BanPolicyContract>.Fail("INVALID_BAN_POLICY_WINDOW", "统计窗口必须是 1 至 2147483647 之间的整数秒。"),
        "observeSeconds" => ApiResult<BanPolicyContract>.Fail("INVALID_BAN_POLICY_OBSERVE", "观察期必须是 0 至 2147483647 之间的整数秒。"),
        "cooldownSeconds" => ApiResult<BanPolicyContract>.Fail("INVALID_BAN_POLICY_COOLDOWN", "冷却期必须是 0 至 2147483647 之间的整数秒。"),
        "banDurationSeconds" => ApiResult<BanPolicyContract>.Fail("INVALID_BAN_POLICY_DURATION", "封禁时长必须为整数。0 表示不封禁，-1 表示永久封禁，1 至 2147483647 表示限时秒数。"),
        _ => ApiResult<BanPolicyContract>.Fail("INVALID_BAN_POLICY", "策略内容无效，请检查名称、动作及各项数值。")
    };
}
