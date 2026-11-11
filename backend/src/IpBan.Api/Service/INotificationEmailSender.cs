using IpBan.Shared.Models;

namespace IpBan.Api.Service;

/// <summary>投递接口便于隔离验证；成功仅表示 SMTP 服务端已接受邮件。</summary>
public interface INotificationEmailSender
{
    Task<NotificationSendResult> SendAsync(NotificationSettings settings, string credential,
        NotificationEmailEnvelope mail, CancellationToken cancellationToken);
}
