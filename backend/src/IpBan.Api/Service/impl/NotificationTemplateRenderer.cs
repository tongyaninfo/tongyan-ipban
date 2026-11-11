using System.Globalization;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using IpBan.Shared.Models;

namespace IpBan.Api.Service.impl;

/// <summary>固定 HTML 资源与受控占位符渲染；所有事件字段编码后插入，禁止模板执行代码或访问外部资源。</summary>
public sealed partial class NotificationTemplateRenderer
{
    public const string CurrentTemplateVersion = "2026-11-11.1";
    private const string SubjectPrefix = "通研IPBan-";
    private static readonly string[] TemplateNames = ["Layout", "LoginSuccess", "LoginFailed", "Ban", "Unban", "Summary", "Test"];
    private readonly Dictionary<string, string> templates;

    public NotificationTemplateRenderer()
    {
        // 启动即读取全部模板；发布遗漏会在启动期显式暴露，而不是等安全事件发生后才失败。
        templates = TemplateNames.ToDictionary(name => name, ReadTemplate, StringComparer.Ordinal);
    }

    public NotificationRenderedEmail Render(NotificationEventSnapshot snapshot, int eventCount = 1, DateTimeOffset? lastOccurredAtUtc = null)
        => RenderCore(snapshot, Math.Max(1, eventCount), lastOccurredAtUtc ?? snapshot.OccurredAtUtc, []);

    public NotificationRenderedEmail RenderSummary(IReadOnlyList<NotificationEventSnapshot> events, int? totalCount = null,
        DateTimeOffset? lastOccurredAtUtc = null, DateTimeOffset? initialNotifiedAtUtc = null)
    {
        ArgumentNullException.ThrowIfNull(events);
        if (events.Count == 0) throw new ArgumentException("通知汇总至少需要一条事件。", nameof(events));
        var ordered = events.OrderBy(item => item.OccurredAtUtc).ToArray();
        return RenderCore(ordered[0], Math.Max(ordered.Length, totalCount ?? ordered.Length),
            lastOccurredAtUtc ?? ordered[^1].OccurredAtUtc, ordered, initialNotifiedAtUtc);
    }

    private NotificationRenderedEmail RenderCore(NotificationEventSnapshot snapshot, int eventCount,
        DateTimeOffset lastOccurredAtUtc, NotificationEventSnapshot[] events, DateTimeOffset? initialNotifiedAtUtc = null)
    {
        var presentation = Describe(snapshot);
        var summary = eventCount > 1 || snapshot.EventType == "summary" || initialNotifiedAtUtc.HasValue;
        var displayedCount = eventCount + (initialNotifiedAtUtc.HasValue ? 1L : 0L);
        var summaryStartedAtUtc = initialNotifiedAtUtc ?? snapshot.OccurredAtUtc;
        var countNote = initialNotifiedAtUtc.HasValue ? $"含已单独通知的首条 1 次，本封新增 {eventCount} 次" : null;
        var summaryDescription = countNote is null ? $"本次合并 {eventCount} 条事件。" : $"本轮累计 {displayedCount} 次（{countNote}）。";
        var title = summary ? $"{EventLabel(snapshot.EventType)}汇总" : presentation.Title;
        // 汇总沿用首条新增事件的快照，其他事件仍在邮件明细中列出。
        var subject = snapshot.EventType is "loginSuccess" or "loginFailure"
            ? $"{SubjectPrefix}{title} {SubjectPart(snapshot.SourceIp)}->{SubjectPart(snapshot.Username)}@{SubjectPart(snapshot.LocalIp)}"
            : SubjectPrefix + title;
        var details = DetailFields(snapshot);
        var tokens = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Title"] = Encode(title),
            ["Preheader"] = Encode($"{snapshot.HostName} · {title} · {DisplayTime(snapshot.OccurredAtUtc)}"),
            ["HostName"] = Encode(DisplayValue(snapshot.HostName)),
            ["OccurredAt"] = Encode(DisplayTime(snapshot.OccurredAtUtc)),
            ["SummaryStartedAt"] = Encode(DisplayTime(summaryStartedAtUtc)),
            ["LastOccurredAt"] = Encode(DisplayTime(lastOccurredAtUtc)),
            ["AccentColor"] = summary ? "#3168da" : presentation.Color,
            ["BadgeBackground"] = summary ? "#eef4ff" : presentation.Background,
            ["StatusLabel"] = Encode(summary ? "合并摘要" : presentation.Status),
            ["OutcomeDescription"] = Encode(presentation.Description),
            ["EventCount"] = displayedCount.ToString(CultureInfo.InvariantCulture),
            ["CountLabel"] = initialNotifiedAtUtc.HasValue ? "本轮累计" : "本次合并事件",
            ["CountNote"] = countNote is null ? "" : $"<p style=\"margin:8px 0 0;color:#475569;font-size:12px;line-height:1.8;\">{Encode(countNote)}。</p>",
            ["Guidance"] = Encode(summary
                ? "摘要中的时间和执行状态来自事件发生时的快照。邮件详情保留有限事件样本，完整主机事件请结合登录与封禁记录查询，不要仅根据摘要推断当前防火墙状态。"
                : presentation.Guidance),
            ["Details"] = RenderDetails(details),
            ["EventRows"] = summary ? RenderEventRows(events, eventCount) : ""
        };
        tokens["Content"] = Fill(templates[summary ? "Summary" : presentation.Template], tokens);
        var html = Fill(templates["Layout"], tokens);
        var text = new StringBuilder()
            .AppendLine(subject)
            .AppendLine(summary ? $"{summaryDescription}以下为本封首条新增事件的快照。" : presentation.Description);
        if (summary) text.AppendLine($"统计时间：{DisplayTime(summaryStartedAtUtc)} — {DisplayTime(lastOccurredAtUtc)}");
        foreach (var (label, value) in details) text.AppendLine($"{label}：{value}");
        if (summary && events.Length > 0)
        {
            text.AppendLine().AppendLine("关联事件（最多展示 20 条）：");
            foreach (var item in events.Take(20))
                text.AppendLine($"{DisplayTime(item.OccurredAtUtc)} | {DisplayValue(item.SourceIp)} | {DisplayValue(item.Username)} | {StatusLabel(item)}");
            if (eventCount > Math.Min(events.Length, 20)) text.AppendLine($"另有 {eventCount - Math.Min(events.Length, 20)} 次事件未在本邮件逐条展开；邮件详情保留 {events.Length} 条事件样本。");
        }
        text.AppendLine().AppendLine(summary ? "完整主机事件请结合管理台登录与封禁记录查询，并核对当前防火墙状态。" : presentation.Guidance)
            .AppendLine("通研技术 · 通研 IPBan | 自动发送，请勿直接回复。")
            .AppendLine("时间均为北京时间（UTC+08:00）。");
        return new(subject, html, text.ToString(), CurrentTemplateVersion);
    }

    private static Presentation Describe(NotificationEventSnapshot item) => item.EventType switch
    {
        "loginSuccess" => new("LoginSuccess", "登录成功通知", "认证成功", "#14805e", "#e9f7f1",
            "主机检测到一次登录成功事件。", "若这不是预期的登录，请核对账号和来源，并在管理台检查当前连接与会话。"),
        "loginFailure" => new("LoginFailed", "登录失败通知", "认证失败", "#b76316", "#fff4e6",
            "主机检测到一次登录失败事件。", "登录失败不代表已经封禁。是否执行封禁，以安全策略和防火墙动作记录为准。"),
        "ban" when item.Status == "Applied" => new("Ban", "封禁成功通知", "防火墙已生效", "#c2424b", "#fff0f1",
            "本次封禁已由防火墙执行成功，来源地址的新连接将按对应规则受到限制。", "普通封禁不保证已建立会话立即断开；当前连接及会话状态请以管理台实际查询为准。"),
        "ban" when item.Status == "Disabled" => new("Ban", "封禁未生效通知", "防火墙关闭", "#b76316", "#fff4e6",
            "已产生封禁决定，但防火墙处于关闭状态，本次封禁未写入防火墙。", "请检查本机防火墙状态。本通知不会自动开启防火墙或补写历史规则。"),
        "ban" => new("Ban", item.Status == "Failed" ? "封禁失败通知" : "封禁结果通知", StatusLabel(item), "#c2424b", "#fff0f1",
            "本次封禁未确认生效，请查看执行状态与原因。", "请检查本机防火墙与执行器状态。只有 Applied 结果表示本次防火墙封禁成功。"),
        "unban" when item.Status == "Removed" => new("Unban", "解封成功通知", "封禁已解除", "#3168da", "#eef4ff",
            "本次解封已由防火墙执行成功，对应的 IPBan 封禁规则已解除。", "解封不代表其他安全规则已解除，也不保证目标服务可连接；请按实际网络和服务状态判断。"),
        "unban" => new("Unban", item.Status == "Disabled" ? "解封未生效通知" : "解封失败通知", StatusLabel(item), "#b76316", "#fff4e6",
            "本次解封未确认成功，不能据此认定来源地址已恢复访问。", "只有实际 Removed 结果才会发送解封成功通知，预计到期时间不代表已经完成解封。"),
        "test" => new("Test", "邮件服务测试", "连接测试", "#3168da", "#eef4ff",
            "这是一封邮件服务测试通知。", "测试邮件仅验证本次配置与投递链路。安全通知还需要启用总开关和对应事件规则。"),
        "summary" => new("Summary", "安全事件汇总", "合并摘要", "#3168da", "#eef4ff", "安全事件通知汇总。", "请在管理台查看完整记录。"),
        _ => throw new ArgumentException("不支持的通知事件类型。", nameof(item))
    };

    private static List<(string Label, string Value)> DetailFields(NotificationEventSnapshot item)
    {
        var fields = new List<(string Label, string Value)>
        {
            ("受保护主机", DisplayValue(item.HostName)), ("事件类型", EventLabel(item.EventType)),
            ("发生时间", DisplayTime(item.OccurredAtUtc)), ("事件状态", StatusLabel(item))
        };
        if (item.EventType != "test")
        {
            fields.Add(("来源地址", DisplayValue(item.SourceIp)));
            fields.Add(("协议", DisplayValue(item.Protocol)));
            fields.Add(("登录账号", DisplayValue(item.Username)));
        }
        if (item.EventType is "ban" or "unban")
        {
            fields.Add(("触发动作", ActionLabel(item.Action)));
            fields.Add(("执行器", DisplayValue(item.Provider)));
            fields.Add(("原因", DisplayValue(item.Reason, 1000)));
            fields.Add(("封禁时长", item.DurationSeconds switch { -1 => "永久（需手动解封）", 0 => "仅观察，不执行封禁", null => "未提供", var value => $"{value} 秒" }));
            if (item.OriginalActionId is not null) fields.Add(("原封禁记录", DisplayValue(item.OriginalActionId)));
        }
        fields.Add(("来源记录", DisplayValue(item.SourceId)));
        return fields;
    }

    private static string RenderDetails(IEnumerable<(string Label, string Value)> fields)
    {
        var builder = new StringBuilder("<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"border:1px solid #e7ecf4;border-radius:8px;border-collapse:separate;table-layout:fixed;\">");
        foreach (var (label, value) in fields)
            builder.Append("<tr><td width=\"112\" style=\"width:112px;padding:11px 12px;background-color:#fafbfe;border-bottom:1px solid #edf0f5;color:#64748b;font-size:12px;vertical-align:top;line-height:1.7;\">")
                .Append(Encode(label)).Append("</td><td style=\"padding:11px 14px;border-bottom:1px solid #edf0f5;color:#24324b;font-size:13px;line-height:1.7;word-break:break-all;overflow-wrap:anywhere;\">")
                .Append(Encode(value)).Append("</td></tr>");
        return builder.Append("</table>").ToString();
    }

    private static string RenderEventRows(NotificationEventSnapshot[] events, int eventCount)
    {
        if (events.Length == 0) return "";
        var builder = new StringBuilder("<p style=\"margin:24px 0 12px;color:#172b50;font-size:14px;font-weight:700;\">关联事件</p><table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"border:1px solid #e7ecf4;border-radius:8px;table-layout:fixed;\">");
        foreach (var item in events.Take(20))
            builder.Append("<tr><td style=\"padding:12px 14px;border-bottom:1px solid #edf0f5;font-size:12px;line-height:1.8;word-break:break-all;\"><strong style=\"color:#24324b;\">")
                .Append(Encode(StatusLabel(item))).Append("</strong><br><span style=\"color:#64748b;\">")
                .Append(Encode(DisplayTime(item.OccurredAtUtc))).Append("<br>")
                .Append(Encode($"来源：{DisplayValue(item.SourceIp)} · 账号：{DisplayValue(item.Username)} · 协议：{DisplayValue(item.Protocol)}"))
                .Append("</span></td></tr>");
        builder.Append("</table>");
        if (eventCount > Math.Min(events.Length, 20))
            builder.Append("<p style=\"font-size:12px;color:#64748b;line-height:1.8;\">另有 ").Append(eventCount - Math.Min(events.Length, 20))
                .Append(" 次事件未在本邮件逐条展开；邮件详情保留 ").Append(events.Length).Append(" 条事件样本。完整主机事件请结合登录与封禁记录查询。</p>");
        return builder.ToString();
    }

    private static string EventLabel(string type) => type switch
    { "loginSuccess" => "登录成功", "loginFailure" => "登录失败", "ban" => "封禁", "unban" => "解封", "test" => "邮件服务测试", _ => "安全事件" };

    private static string StatusLabel(NotificationEventSnapshot item) => item.Status switch
    {
        "Test" => "测试通知", "Success" => item.EventType == "test" ? "测试通知" : "认证成功",
        "Failure" => "认证失败", "Applied" => "防火墙已生效", "Removed" => "封禁已解除",
        "Disabled" => "防火墙关闭，未确认执行成功", "Failed" => "执行失败", "Pending" => "等待执行",
        _ => DisplayValue(item.Status)
    };

    private static string ActionLabel(string? action) => action switch
    { "ban" => "人工封禁", "auto-ban" => "自动策略封禁", "manual-unban" => "人工解封", "unban" or "auto-unban" => "到期解封", _ => DisplayValue(action) };

    private static string DisplayTime(DateTimeOffset time) => time.ToOffset(TimeSpan.FromHours(8)).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
    private static string DisplayValue(string? value, int limit = 240) => string.IsNullOrWhiteSpace(value) ? "未提供" : value.Length <= limit ? value : value[..limit] + "…";
    private static string SubjectPart(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "未提供";
        // 账号来自登录事件，邮件标题只保留单行文本。
        var text = string.Concat(value.Select(character =>
            char.IsControl(character) || character is '\u2028' or '\u2029' ? ' ' : character)).Trim();
        if (text.Length <= 128) return DisplayValue(text);
        var length = char.IsHighSurrogate(text[127]) ? 127 : 128;
        return text[..length] + "…";
    }

    private static string Encode(string value) => WebUtility.HtmlEncode(value);
    private static string Fill(string template, Dictionary<string, string> tokens) => Placeholder().Replace(template,
        match => tokens.TryGetValue(match.Groups[1].Value, out var value) ? value : throw new InvalidOperationException("邮件模板包含未定义占位符。"));

    private static string ReadTemplate(string name)
    {
        using var stream = typeof(NotificationTemplateRenderer).Assembly.GetManifestResourceStream($"IpBan.Api.Resources.EmailTemplates.{name}.html")
            ?? throw new InvalidOperationException($"缺少邮件模板资源：{name}。");
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    [GeneratedRegex(@"\{\{([A-Za-z]+)\}\}", RegexOptions.CultureInvariant)]
    private static partial Regex Placeholder();
    private sealed record Presentation(string Template, string Title, string Status, string Color, string Background, string Description, string Guidance);
}
