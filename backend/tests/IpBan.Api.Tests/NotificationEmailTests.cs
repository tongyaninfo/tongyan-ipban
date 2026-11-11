using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using IpBan.Api.Options;
using IpBan.Api.Service.impl;
using IpBan.Shared.Models;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;

namespace IpBan.Api.Tests;

public sealed class NotificationEmailTests
{
    [Theory]
    [InlineData("loginSuccess", "Success", "通研IPBan-登录成功通知 192.0.2.5->fixture-user@198.51.100.20")]
    [InlineData("loginFailure", "Failure", "通研IPBan-登录失败通知 192.0.2.5->fixture-user@198.51.100.20")]
    [InlineData("ban", "Applied", "通研IPBan-封禁成功通知")]
    [InlineData("ban", "Disabled", "通研IPBan-封禁未生效通知")]
    [InlineData("ban", "Failed", "通研IPBan-封禁失败通知")]
    [InlineData("unban", "Removed", "通研IPBan-解封成功通知")]
    [InlineData("unban", "Failed", "通研IPBan-解封失败通知")]
    [InlineData("test", "Success", "通研IPBan-邮件服务测试")]
    [InlineData("test", "Test", "通研IPBan-邮件服务测试")]
    public void TemplatesHaveExactSubjectAndPlainTextAlternative(string type, string status, string subject)
    {
        var result = new NotificationTemplateRenderer().Render(Event(type, status));
        Assert.Equal(subject, result.Subject);
        Assert.Contains("<!doctype html>", result.HtmlBody, StringComparison.Ordinal);
        Assert.Contains("max-width:640px", result.HtmlBody, StringComparison.Ordinal);
        Assert.DoesNotContain("{{", result.HtmlBody, StringComparison.Ordinal);
        Assert.DoesNotContain("<script", result.HtmlBody, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("https://", result.HtmlBody, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("2026-11-10 20:00:00", result.TextBody, StringComparison.Ordinal);
        Assert.Contains(subject, result.TextBody, StringComparison.Ordinal);
        Assert.Equal(NotificationTemplateRenderer.CurrentTemplateVersion, result.TemplateVersion);
    }

    [Fact]
    public void LoginSubjectUsesSingleLineAndMarksMissingAddresses()
    {
        var login = Event("loginFailure", "Failure") with
        { SourceIp = null, LocalIp = null, Username = "演示\r\n账号" };
        var result = new NotificationTemplateRenderer().Render(login);
        Assert.Equal("通研IPBan-登录失败通知 未提供->演示  账号@未提供", result.Subject);
    }

    [Fact]
    public void LoginSummarySubjectUsesFirstNewEventInTimeOrder()
    {
        var first = Event("loginFailure", "Failure");
        var later = first with
        {
            Username = "another-user", LocalIp = "198.51.100.21",
            OccurredAtUtc = first.OccurredAtUtc.AddSeconds(10),
        };
        var result = new NotificationTemplateRenderer().RenderSummary([later, first]);
        Assert.Equal("通研IPBan-登录失败汇总 192.0.2.5->fixture-user@198.51.100.20", result.Subject);
    }

    [Fact]
    public void TemplateEncodesAllUntrustedFieldsWithoutRecursivePlaceholderEvaluation()
    {
        const string input = "<img src=x onerror=alert(1)>{{Title}}&\"";
        var result = new NotificationTemplateRenderer().Render(Event("ban", "Failed") with
        { HostName = input, Username = input, SourceIp = input, Protocol = input, Reason = input, Provider = input, OriginalActionId = input });
        Assert.DoesNotContain("<img src=x", result.HtmlBody, StringComparison.Ordinal);
        Assert.Contains("&lt;img", result.HtmlBody, StringComparison.Ordinal);
        Assert.Contains("{{Title}}", result.HtmlBody, StringComparison.Ordinal);
        Assert.DoesNotContain("封禁成功通知", result.Subject, StringComparison.Ordinal);
    }

    [Fact]
    public void SummaryShowsDistinctStatesAndBoundsEventRows()
    {
        var records = Enumerable.Range(0, 24).Select(index => Event("ban", index % 2 == 0 ? "Applied" : "Failed") with
        { Username = $"user-{index}", OccurredAtUtc = DateTimeOffset.Parse("2026-11-10T12:00:00Z", System.Globalization.CultureInfo.InvariantCulture).AddMinutes(index) }).Reverse().ToArray();
        var result = new NotificationTemplateRenderer().RenderSummary(records);
        Assert.Equal("通研IPBan-封禁汇总", result.Subject);
        Assert.Contains("本次合并 24 条事件", result.TextBody, StringComparison.Ordinal);
        Assert.Contains("防火墙已生效", result.HtmlBody, StringComparison.Ordinal);
        Assert.Contains("执行失败", result.HtmlBody, StringComparison.Ordinal);
        Assert.Contains("user-19", result.HtmlBody, StringComparison.Ordinal);
        Assert.DoesNotContain("user-20", result.HtmlBody, StringComparison.Ordinal);
        Assert.Contains("另有 4 次事件", result.TextBody, StringComparison.Ordinal);
        Assert.Contains("2026-11-10 20:23:00", result.TextBody, StringComparison.Ordinal);
    }

    [Fact]
    public void SummaryPreservesFullCountAndLastTimeWhenSnapshotsAreSampled()
    {
        var last = Event("loginFailure", "Failure").OccurredAtUtc.AddHours(1);
        var records = Enumerable.Range(0, 100).Select(index => Event("loginFailure", "Failure") with { SourceId = index.ToString(System.Globalization.CultureInfo.InvariantCulture) }).ToArray();
        var result = new NotificationTemplateRenderer().RenderSummary(records, totalCount: 10000, lastOccurredAtUtc: last);
        Assert.Contains("本次合并 10000 条事件", result.TextBody, StringComparison.Ordinal);
        Assert.Contains("2026-11-10 21:00:00", result.TextBody, StringComparison.Ordinal);
        Assert.Contains("另有 9980 次事件", result.TextBody, StringComparison.Ordinal);
        Assert.Contains("邮件详情保留 100 条事件样本", result.TextBody, StringComparison.Ordinal);
    }

    [Fact]
    public void CredentialRoundTripsUsesRandomNonceAndDetectsTampering()
    {
        var (protector, directory) = Protector();
        const string value = "synthetic-authorization-code";
        var first = protector.Protect(value);
        var second = protector.Protect(value, allowCreateMasterKey: false);
        Assert.NotEqual(first, second);
        Assert.Equal(value, protector.Unprotect(first));
        Assert.DoesNotContain(value, first, StringComparison.Ordinal);
        var payload = Convert.FromBase64String(first);
        payload[^1] ^= 1;
        Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(Convert.ToBase64String(payload)));
        Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect("not-base64"));
        if (!OperatingSystem.IsWindows())
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Path.Combine(directory, "notifications-key-protection.bin")));
    }

    [Fact]
    public void MissingKeyAndInsecurePermissionsAreNeverRecreatedForExistingCredential()
    {
        var (protector, directory) = Protector();
        Assert.ThrowsAny<IOException>(() => protector.Protect("synthetic", allowCreateMasterKey: false));
        var payload = protector.Protect("synthetic");
        if (!OperatingSystem.IsWindows())
        {
            var keyPath = Path.Combine(directory, "notifications-key-protection.bin");
            File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
            Assert.Throws<UnauthorizedAccessException>(() => protector.Unprotect(payload));
            File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        var (otherProtector, _) = Protector();
        Assert.ThrowsAny<IOException>(() => otherProtector.Unprotect(payload));
    }

    [Theory]
    [InlineData(250, true, false, null)]
    [InlineData(450, false, true, "SMTP_TEMPORARILY_REJECTED")]
    [InlineData(550, false, false, "SMTP_REJECTED")]
    public async Task SmtpUsesSavedEnvelopeAndClassifiesServerResults(int response, bool success, bool retryable, string? code)
    {
        await using var server = new LocalSmtpServer(response);
        var settings = new NotificationSettings { Host = "127.0.0.1", Port = server.Port, Security = "none", Username = "sender@example.test", FromAddress = "sender@example.test" };
        var envelope = new NotificationEmailEnvelope("fixture-message@example.test", "recipient@example.test", "通研IPBan-邮件服务测试", "<p>synthetic html</p>", "synthetic text");
        var result = await new NotificationEmailSender().SendAsync(settings, "synthetic-auth-code", envelope, CancellationToken.None);
        Assert.Equal(success, result.Success);
        Assert.Equal(retryable, result.Retryable);
        Assert.Equal(code, result.ErrorCode);
        Assert.DoesNotContain("sensitive fixture detail", result.ErrorMessage ?? "", StringComparison.Ordinal);
        if (success)
        {
            using var message = MimeKit.MimeMessage.Load(new MemoryStream(Encoding.UTF8.GetBytes(server.Data)));
            Assert.Equal(envelope.Subject, message.Subject);
            Assert.Equal(envelope.MessageId, message.MessageId);
            Assert.Equal(envelope.Recipient, Assert.Single(message.To.Mailboxes).Address);
            Assert.Equal(envelope.HtmlBody, message.HtmlBody?.TrimEnd('\r', '\n'));
            Assert.Equal(envelope.TextBody, message.TextBody?.TrimEnd('\r', '\n'));
        }
    }

    [Fact]
    public async Task StartTlsRequirementDoesNotDowngradeWhenServerDoesNotOfferIt()
    {
        await using var server = new LocalSmtpServer(250);
        var settings = new NotificationSettings { Host = "127.0.0.1", Port = server.Port, Security = "starttls", Username = "sender@example.test", FromAddress = "sender@example.test" };
        var result = await new NotificationEmailSender().SendAsync(settings, "synthetic", Envelope(), CancellationToken.None);
        Assert.False(result.Success);
        Assert.False(result.Retryable);
        Assert.Equal("SMTP_MODE_UNSUPPORTED", result.ErrorCode);
        Assert.False(server.Authenticated);
        Assert.Empty(server.Data);
    }

    [Fact]
    public async Task AuthenticationFailureDoesNotLeakServerResponseOrRetry()
    {
        await using var server = new LocalSmtpServer(250, authenticationAccepted: false);
        var settings = new NotificationSettings { Host = "127.0.0.1", Port = server.Port, Security = "none", Username = "sender@example.test", FromAddress = "sender@example.test" };
        var result = await new NotificationEmailSender().SendAsync(settings, "synthetic", Envelope(), CancellationToken.None);
        Assert.False(result.Success);
        Assert.False(result.Retryable);
        Assert.Equal("SMTP_AUTHENTICATION_FAILED", result.ErrorCode);
        Assert.DoesNotContain("sensitive fixture detail", result.ErrorMessage ?? "", StringComparison.Ordinal);
        Assert.Empty(server.Data);
    }

    [Fact]
    public async Task AcceptedMessageIsNotRetriedWhenDisconnectFails()
    {
        await using var server = new LocalSmtpServer(250, disconnectAfterAccept: true);
        var settings = new NotificationSettings { Host = "127.0.0.1", Port = server.Port, Security = "none", Username = "sender@example.test", FromAddress = "sender@example.test" };
        var result = await new NotificationEmailSender().SendAsync(settings, "synthetic", Envelope(), CancellationToken.None);
        Assert.True(result.Success);
        Assert.False(result.Retryable);
    }

    [Fact]
    public async Task ImplicitTlsRejectsUntrustedCertificateWithoutSendingCredentials()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName("localhost");
        names.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(names.Build());
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var server = Task.Run(async () =>
        {
            using var socket = await listener.AcceptTcpClientAsync(stop.Token);
            await using var stream = new SslStream(socket.GetStream());
            try { await stream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = certificate }, stop.Token); }
            catch (Exception exception) when (exception is IOException or System.Security.Authentication.AuthenticationException) { }
        });
        var settings = new NotificationSettings { Host = "127.0.0.1", Port = port, Security = "ssl", Username = "sender@example.test", FromAddress = "sender@example.test" };
        var result = await new NotificationEmailSender().SendAsync(settings, "synthetic", Envelope(), CancellationToken.None);
        Assert.False(result.Success);
        Assert.False(result.Retryable);
        Assert.Equal("SMTP_TLS_FAILED", result.ErrorCode);
        await server;
    }

    [Fact]
    public async Task CallerCancellationIsNotReportedAsAnSmtpFailure()
    {
        var settings = new NotificationSettings { Host = "127.0.0.1", Port = 1, Security = "none", Username = "sender@example.test", FromAddress = "sender@example.test" };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new NotificationEmailSender().SendAsync(settings, "synthetic", Envelope(), new CancellationToken(true)));
    }

    private static NotificationEventSnapshot Event(string type, string status) => new(type, "42", "synthetic-host", "192.0.2.5", "Ssh", "fixture-user",
        DateTimeOffset.Parse("2026-11-10T12:00:00Z", System.Globalization.CultureInfo.InvariantCulture), status, "auto-ban", "合成测试事件", 300, "fixture-firewall",
        LocalIp: "198.51.100.20");
    private static NotificationEmailEnvelope Envelope() => new("fixture@example.test", "recipient@example.test", "通研IPBan-测试", "<p>test</p>", "test");

    private static (NotificationCredentialProtector Protector, string Directory) Protector()
    {
        var directory = Path.Combine(Path.GetTempPath(), "ipban-notification-email-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var admin = new SqliteAdminStore(Microsoft.Extensions.Options.Options.Create(new ManagementDataOptions { DataDirectory = directory }), new TestEnvironment(directory));
        return (new NotificationCredentialProtector(admin), directory);
    }

    private sealed class TestEnvironment(string directory) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Test";
        public string ApplicationName { get; set; } = "IpBan.Api.Tests";
        public string ContentRootPath { get; set; } = directory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    /// <summary>仅绑定回环地址的合成 SMTP 接收端，不向外部邮箱发送任何邮件。</summary>
    private sealed class LocalSmtpServer : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource stop = new(TimeSpan.FromSeconds(20));
        private readonly Task task;
        public int Port { get; }
        public string Data { get; private set; } = "";
        public bool Authenticated { get; private set; }

        public LocalSmtpServer(int response, bool authenticationAccepted = true, bool disconnectAfterAccept = false)
        {
            listener.Start();
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;
            task = RunAsync(response, authenticationAccepted, disconnectAfterAccept);
        }

        private async Task RunAsync(int response, bool authenticationAccepted, bool disconnectAfterAccept)
        {
            using var socket = await listener.AcceptTcpClientAsync(stop.Token);
            await using var stream = socket.GetStream();
            using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
            await using var writer = new StreamWriter(stream, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true, NewLine = "\r\n" };
            await writer.WriteLineAsync("220 localhost ESMTP");
            while (await reader.ReadLineAsync(stop.Token) is { } line)
            {
                if (line.StartsWith("EHLO", StringComparison.Ordinal))
                    await writer.WriteLineAsync("250-localhost\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 1048576");
                else if (line.StartsWith("AUTH", StringComparison.Ordinal))
                {
                    Authenticated = authenticationAccepted;
                    await writer.WriteLineAsync(authenticationAccepted ? "235 2.7.0 accepted" : "535 5.7.8 sensitive fixture detail");
                }
                else if (line.StartsWith("MAIL FROM", StringComparison.Ordinal)) await writer.WriteLineAsync("250 accepted");
                else if (line.StartsWith("RCPT TO", StringComparison.Ordinal))
                    await writer.WriteLineAsync(response == 250 ? "250 accepted" : $"{response} sensitive fixture detail");
                else if (line == "DATA")
                {
                    await writer.WriteLineAsync("354 end with dot");
                    var data = new StringBuilder();
                    while (await reader.ReadLineAsync(stop.Token) is { } body && body != ".") data.Append(body).Append("\r\n");
                    Data = data.ToString();
                    await writer.WriteLineAsync("250 queued");
                    if (disconnectAfterAccept) return;
                }
                else if (line == "QUIT") { await writer.WriteLineAsync("221 bye"); return; }
                else if (line == "RSET") await writer.WriteLineAsync("250 reset");
                else await writer.WriteLineAsync("500 unsupported fixture command");
            }
        }

        public async ValueTask DisposeAsync()
        {
            await stop.CancelAsync();
            listener.Stop();
            try { await task; }
            catch (Exception exception) when (exception is OperationCanceledException or IOException or SocketException) { }
            stop.Dispose();
        }
    }
}
