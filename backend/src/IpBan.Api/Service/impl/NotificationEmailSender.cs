using System.Net.Sockets;
using IpBan.Shared.Models;
using MailKit;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace IpBan.Api.Service.impl;

/// <summary>每次投递独立 SMTP 连接；强制选定 TLS 模式，不降低证书校验，不输出服务器响应或授权码。</summary>
public sealed class NotificationEmailSender : INotificationEmailSender
{
    public async Task<NotificationSendResult> SendAsync(NotificationSettings settings, string credential,
        NotificationEmailEnvelope mail, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(15));
        try
        {
            var security = settings.Security switch
            {
                "ssl" => SecureSocketOptions.SslOnConnect,
                "starttls" => SecureSocketOptions.StartTls,
                "none" => SecureSocketOptions.None,
                _ => throw new ArgumentException("无效的邮件连接安全模式。", nameof(settings))
            };
            if (string.IsNullOrWhiteSpace(credential))
                return new(false, false, "SMTP_CREDENTIAL_REQUIRED", "请先配置邮件授权码。");
            using var message = new MimeMessage();
            message.From.Add(new MailboxAddress(settings.FromName, settings.FromAddress));
            message.To.Add(MailboxAddress.Parse(mail.Recipient));
            message.Subject = mail.Subject;
            message.MessageId = mail.MessageId;
            message.Body = new BodyBuilder { HtmlBody = mail.HtmlBody, TextBody = mail.TextBody }.ToMessageBody();

            // 不启用协议日志，使用 MailKit 默认的主机名与证书链校验。
            using var client = new SmtpClient { Timeout = 15_000 };
            await client.ConnectAsync(settings.Host, settings.Port, security, deadline.Token).ConfigureAwait(false);
            // 本期授权码认证不尝试 OAuth，避免把授权码当作访问令牌发送。
            client.AuthenticationMechanisms.Remove("XOAUTH2");
            client.AuthenticationMechanisms.Remove("OAUTHBEARER");
            await client.AuthenticateAsync(settings.Username, credential, deadline.Token).ConfigureAwait(false);
            await client.SendAsync(message, deadline.Token).ConfigureAwait(false);
            // DATA 已获服务器确认，QUIT 失败不能触发重发，否则正常已接受的邮件会重复。
            try { await client.DisconnectAsync(true, deadline.Token).ConfigureAwait(false); }
            catch (Exception exception) when (exception is IOException or SocketException or OperationCanceledException or SmtpCommandException or SmtpProtocolException or ServiceNotConnectedException) { }
            return new(true, false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { return new(false, true, "SMTP_TIMEOUT", "邮件服务器连接或发送超时，将按重试规则处理。"); }
        catch (MailKit.Security.AuthenticationException)
        { return new(false, false, "SMTP_AUTHENTICATION_FAILED", "邮件服务器认证失败，请检查登录账号、授权码和 SMTP 服务状态。"); }
        catch (SslHandshakeException)
        { return new(false, false, "SMTP_TLS_FAILED", "邮件加密连接或证书校验失败，请检查服务器地址、端口和加密方式。"); }
        catch (System.Security.Authentication.AuthenticationException)
        { return new(false, false, "SMTP_TLS_FAILED", "邮件加密连接或证书校验失败，请检查服务器地址、端口和加密方式。"); }
        catch (SmtpCommandException exception)
        {
            var retryable = (int)exception.StatusCode is >= 400 and < 500;
            return new(false, retryable, retryable ? "SMTP_TEMPORARILY_REJECTED" : "SMTP_REJECTED",
                retryable ? "邮件服务器暂时拒绝投递，将按重试规则处理。" : "邮件服务器拒绝投递，请检查发件地址、收件地址及服务器发送策略。");
        }
        catch (NotSupportedException)
        { return new(false, false, "SMTP_MODE_UNSUPPORTED", "邮件服务器不支持所选加密或认证方式。"); }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        { return new(false, false, "SMTP_CONFIGURATION_INVALID", "邮件配置或地址格式无效，请检查后重试。"); }
        catch (Exception exception) when (exception is IOException or SocketException or SmtpProtocolException or ServiceNotConnectedException)
        { return new(false, true, "SMTP_CONNECTION_FAILED", "邮件服务器连接中断或不可用，将按重试规则处理。"); }
    }
}
