using System.Text.Json.Serialization;

namespace IpBan.Shared.Models;

/// <summary>通知配置快照；凭据始终经单独的写入字段传递，不回显或混入配置 JSON。</summary>
public sealed record NotificationSettings
{
    public bool Enabled { get; init; }
    public string Host { get; init; } = "";
    public int Port { get; init; } = 465;
    public string Security { get; init; } = "ssl";
    public string FromAddress { get; init; } = "";
    public string Username { get; init; } = "";
    public string FromName { get; init; } = "通研技术";
    public string[] Recipients { get; init; } = [];
    public bool HasCredential { get; init; }
    public int MaxPerMinute { get; init; } = 10;
    public int MaxPerHour { get; init; } = 60;
    public int RetryCount { get; init; } = 3;
    public int RetentionDays { get; init; } = 30;
    public int QueueLifetimeHours { get; init; } = 24;
    public string Revision { get; init; } = "";
    public DateTimeOffset? EnabledSinceUtc { get; init; }
    public NotificationRule[] Rules { get; init; } =
    [
        new("loginSuccess", true, 300), new("loginFailure", true, 600),
        new("ban", true, 60), new("unban", true, 60)
    ];
}

public sealed record NotificationRule(string EventType, bool Enabled, int IntervalSeconds);
public sealed record UpdateNotificationSettingsRequest(NotificationSettings Settings, string? Credential = null, bool ClearCredential = false);
public sealed record TestNotificationRequest(string Recipient);
public sealed record NotificationTestResult(string[] MessageIds);

/// <summary>保存事件当时的最小快照，缺失字段留空，不从当前策略反推历史事实。</summary>
public sealed record NotificationEventSnapshot(
    string EventType, string SourceId, string HostName, string? SourceIp, string? Protocol,
    string? Username, DateTimeOffset OccurredAtUtc, string Status,
    string? Action = null, string? Reason = null, int? DurationSeconds = null,
    string? Provider = null, string? OriginalActionId = null, string? LocalIp = null);

public sealed record NotificationEmailEnvelope(string MessageId, string Recipient, string Subject, string HtmlBody, string TextBody);
public sealed record NotificationSendResult(bool Success, bool Retryable, string? ErrorCode = null, string? ErrorMessage = null);
public sealed record NotificationRenderedEmail(string Subject, string HtmlBody, string TextBody, string TemplateVersion);

public sealed record NotificationMessageSummary(
    string Id, string EventType, string Status, string Recipient, string Subject, string? SourceIp,
    int EventCount, int Attempts, DateTimeOffset CreatedAtUtc, DateTimeOffset? SentAtUtc,
    DateTimeOffset? NextAttemptAtUtc, string? LastErrorCode, string? LastErrorMessage);
public sealed record NotificationMessagePage(NotificationMessageSummary[] Items, long Total, int Page, int PageSize,
    long PendingEvents, long SuppressedEvents);
public sealed record NotificationMessageDetail(NotificationMessageSummary Message, string HtmlBody, string TextBody,
    string TemplateVersion, string MessageId, NotificationEventSnapshot[] Events);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(NotificationSettings))]
[JsonSerializable(typeof(UpdateNotificationSettingsRequest))]
[JsonSerializable(typeof(TestNotificationRequest))]
[JsonSerializable(typeof(NotificationEventSnapshot))]
[JsonSerializable(typeof(NotificationEventSnapshot[]))]
[JsonSerializable(typeof(ApiResult<NotificationSettings>))]
[JsonSerializable(typeof(ApiResult<NotificationMessagePage>))]
[JsonSerializable(typeof(ApiResult<NotificationMessageDetail>))]
[JsonSerializable(typeof(ApiResult<NotificationRenderedEmail>))]
[JsonSerializable(typeof(ApiResult<NotificationTestResult>))]
public sealed partial class NotificationJsonContext : JsonSerializerContext;
