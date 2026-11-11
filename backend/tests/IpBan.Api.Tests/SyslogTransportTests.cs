using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using IpBan.Shared.Logging.Syslog;

namespace IpBan.Api.Tests;

public sealed class SyslogTransportTests
{
    private static readonly SyslogEvent LoginFailure = new(
        "login-test-001", new DateTimeOffset(2026, 11, 11, 12, 30, 40, TimeSpan.FromHours(8)).AddTicks(1234567),
        "HOST01", "ipban-login", "agent", 42, "login.failed", SyslogSeverity.Emergency,
        "登录失败\r\n未通过认证。", Priority: true, Result: "failed", RemoteIp: "192.0.2.14");

    [Fact]
    public void WireUsesModuleAndComputerNameAndPreservesChineseJson()
    {
        var payload = SyslogWire.Format(LoginFailure);
        Assert.StartsWith("<128>1 2026-11-11T04:30:40.123456Z syslog-HOST01 ipban-login 42 login.failed - ",
            Encoding.UTF8.GetString(payload), StringComparison.Ordinal);
        Assert.DoesNotContain((byte)'\r', payload);
        Assert.DoesNotContain((byte)'\n', payload);
        using var json = ReadBody(payload);
        Assert.Equal(LoginFailure.Message, json.RootElement.GetProperty("message").GetString());
        Assert.Equal("P0", json.RootElement.GetProperty("deliveryPriority").GetString());
        Assert.Equal(0, json.RootElement.GetProperty("syslogSeverity").GetInt32());
        Assert.Equal("failed", json.RootElement.GetProperty("result").GetString());
    }

    [Fact]
    public void NonAsciiAndOverlongNamesProduceStableDistinctValidHeaders()
    {
        var name = string.Concat(Enumerable.Repeat("测试主机", 120));
        var first = LoginFailure with { ComputerName = name + "1" };
        var second = first with { ComputerName = name + "2" };
        var hostname = ReadHostname(SyslogWire.Format(first));
        Assert.StartsWith("syslog-", hostname, StringComparison.Ordinal);
        Assert.InRange(hostname.Length, 8, 255);
        Assert.All(hostname, value => Assert.InRange(value, '!', '~'));
        Assert.NotEqual(hostname, ReadHostname(SyslogWire.Format(second)));
        Assert.Equal(hostname, ReadHostname(SyslogWire.Format(first, 480)));
        using var json = ReadBody(SyslogWire.Format(first));
        Assert.Equal(first.ComputerName, json.RootElement.GetProperty("computerName").GetString());
    }

    [Theory]
    [InlineData("127.0.0.1", 480)]
    [InlineData("::1", 1180)]
    public async Task UdpSendsOneValidDatagramWithinAddressFamilyBudget(string host, int budget)
    {
        using var timeout = TestTimeout();
        using var receiver = new UdpClient(new IPEndPoint(IPAddress.Parse(host), 0));
        var endpoint = (IPEndPoint)receiver.Client.LocalEndPoint!;
        await using var transport = new SyslogTransport(Target(endpoint.Port, "udp") with { Host = host });
        var longMessage = string.Concat(Enumerable.Repeat("登录失败😀\n", 500));

        Assert.False(await transport.SendAsync(LoginFailure with { Message = longMessage }, timeout.Token));
        Assert.True(transport.LastSendTruncated);
        var received = await receiver.ReceiveAsync(timeout.Token);

        Assert.InRange(received.Buffer.Length, 1, budget);
        using var json = ReadBody(received.Buffer);
        Assert.Equal(LoginFailure.EventUid, json.RootElement.GetProperty("eventUid").GetString());
        Assert.True(json.RootElement.GetProperty("truncated").GetBoolean());
        var message = json.RootElement.GetProperty("message").GetString();
        Assert.NotNull(message);
        Assert.NotEmpty(message);
        Assert.DoesNotContain('\uFFFD', message);
        Assert.StartsWith(message, longMessage, StringComparison.Ordinal);
        Assert.Equal(0, receiver.Available);
    }

    [Theory]
    [InlineData("octet")]
    [InlineData("lf")]
    public async Task TcpFramesTwoMessagesOnOneConnection(string framing)
    {
        using var timeout = TestTimeout();
        using var listener = StartTcp();
        await using var transport = new SyslogTransport(Target(Port(listener), "tcp") with { Framing = framing });
        var second = LoginFailure with { EventUid = "login-test-002", Message = "第二条日志。" };
        Assert.False(await transport.SendAsync(LoginFailure, timeout.Token));
        Assert.False(await transport.SendAsync(second, timeout.Token));
        using var receiver = await listener.AcceptTcpClientAsync(timeout.Token);
        using var network = receiver.GetStream();

        using var firstJson = ReadBody(await ReadTcpPayloadAsync(network, framing, timeout.Token));
        using var secondJson = ReadBody(await ReadTcpPayloadAsync(network, framing, timeout.Token));
        Assert.Equal(LoginFailure.EventUid, firstJson.RootElement.GetProperty("eventUid").GetString());
        Assert.Equal(second.EventUid, secondJson.RootElement.GetProperty("eventUid").GetString());
    }

    [Fact]
    public async Task TlsValidatesCertificateByDefaultAndCanRelaxOnlyCertificateValidation()
    {
        using var timeout = TestTimeout();
        using var certificate = CreateUntrustedCertificate();
        using var listener = StartTcp();
        var target = Target(Port(listener), "tls");
        await using var strictTransport = new SyslogTransport(target);
        var strictReceiver = ReceiveTlsAsync(listener, certificate, timeout.Token);
        await Assert.ThrowsAsync<AuthenticationException>(() => strictTransport.SendAsync(LoginFailure, timeout.Token));
        var strictError = await Record.ExceptionAsync(async () => await strictReceiver);
        Assert.True(strictError is AuthenticationException or IOException or SocketException);

        await using var relaxedTransport = new SyslogTransport(target with { IgnoreSslErrors = true });
        var relaxedReceiver = ReceiveTlsAsync(listener, certificate, timeout.Token);
        Assert.False(await relaxedTransport.SendAsync(LoginFailure, timeout.Token));
        using var json = ReadBody(await relaxedReceiver);
        Assert.Equal(LoginFailure.Message, json.RootElement.GetProperty("message").GetString());
    }

    [Fact]
    public async Task RelaxedTlsStillRejectsPlainTcpPeer()
    {
        using var timeout = TestTimeout();
        using var listener = StartTcp();
        await using var transport = new SyslogTransport(Target(Port(listener), "tls") with { IgnoreSslErrors = true });
        var sending = transport.SendAsync(LoginFailure, timeout.Token);
        using (var receiver = await listener.AcceptTcpClientAsync(timeout.Token))
        {
            using var network = receiver.GetStream();
            var first = new byte[1];
            await network.ReadExactlyAsync(first.AsMemory(), timeout.Token);
            Assert.Equal(0x16, first[0]); // TLS 握手记录类型。
            await network.WriteAsync("仅提供明文 TCP\n"u8.ToArray(), timeout.Token);
        }

        var error = await Record.ExceptionAsync(async () => await sending);
        Assert.True(error is AuthenticationException or IOException);
    }

    [Fact]
    public async Task RelpChecksTransactionAndReconnectsBeforeRetriedEvent()
    {
        using var timeout = TestTimeout();
        using var listener = StartTcp();
        var receive = ReceiveRelpAsync(listener, timeout.Token);
        await using (var transport = new SyslogTransport(Target(Port(listener), "relp")))
        {
            // 第一次确认使用错误事务号，发送方必须失败并丢弃连接。
            await Assert.ThrowsAsync<IOException>(() => transport.SendAsync(LoginFailure, timeout.Token));
            Assert.True(await transport.SendAsync(LoginFailure, timeout.Token));
        }

        var received = await receive;
        Assert.Equal(new[] { LoginFailure.EventUid, LoginFailure.EventUid }, received);
    }

    private static async Task<string[]> ReceiveRelpAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        var identifiers = new List<string>();
        for (var i = 0; i < 2; i++)
        {
            using var receiver = await listener.AcceptTcpClientAsync(cancellationToken);
            using var network = receiver.GetStream();
            var open = await ReadRelpRequestAsync(network, cancellationToken);
            Assert.Equal("1", open.Transaction);
            Assert.Equal("open", open.Command);
            Assert.Contains("relp_version=0", Encoding.ASCII.GetString(open.Payload), StringComparison.Ordinal);
            Assert.Contains("commands=syslog", Encoding.ASCII.GetString(open.Payload), StringComparison.Ordinal);
            await WriteRelpReplyAsync(network, "1", "200 OK\nrelp_version=0\ncommands=syslog", cancellationToken);

            var syslog = await ReadRelpRequestAsync(network, cancellationToken);
            Assert.Equal("2", syslog.Transaction);
            Assert.Equal("syslog", syslog.Command);
            using var json = ReadBody(syslog.Payload);
            identifiers.Add(json.RootElement.GetProperty("eventUid").GetString()!);
            await WriteRelpReplyAsync(network, i == 0 ? "3" : "2", "200 OK", cancellationToken);

            if (i != 0)
            {
                var close = await ReadRelpRequestAsync(network, cancellationToken);
                Assert.Equal("3", close.Transaction);
                Assert.Equal("close", close.Command);
                Assert.Empty(close.Payload);
                await network.WriteAsync("3 rsp 0\n"u8.ToArray(), cancellationToken);
            }
        }

        return [.. identifiers];
    }

    private static async Task<(string Transaction, string Command, byte[] Payload)> ReadRelpRequestAsync(
        Stream stream, CancellationToken cancellationToken)
    {
        var transaction = Encoding.ASCII.GetString(await ReadUntilAsync(stream, (byte)' ', cancellationToken));
        var command = Encoding.ASCII.GetString(await ReadUntilAsync(stream, (byte)' ', cancellationToken));
        var lengthSeparator = command == "close" ? (byte)'\n' : (byte)' ';
        var length = int.Parse(Encoding.ASCII.GetString(await ReadUntilAsync(stream, lengthSeparator, cancellationToken)),
            CultureInfo.InvariantCulture);
        Assert.InRange(length, 0, 8192);
        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload.AsMemory(), cancellationToken);
        if (length != 0)
            Assert.Empty(await ReadUntilAsync(stream, (byte)'\n', cancellationToken));
        return (transaction, command, payload);
    }

    private static async Task WriteRelpReplyAsync(Stream stream, string transaction, string response,
        CancellationToken cancellationToken)
    {
        var prefix = Encoding.ASCII.GetBytes(FormattableString.Invariant($"{transaction} rsp {response.Length} "));
        var suffix = Encoding.ASCII.GetBytes(response + "\n");
        // 分开写入首部与负载，接收端应按字节长度解析，不依赖读取分块。
        await stream.WriteAsync(prefix.AsMemory(), cancellationToken);
        await stream.WriteAsync(suffix.AsMemory(), cancellationToken);
    }

    private static async Task<byte[]> ReceiveTlsAsync(TcpListener listener, X509Certificate2 certificate,
        CancellationToken cancellationToken)
    {
        using var receiver = await listener.AcceptTcpClientAsync(cancellationToken);
        using var ssl = new SslStream(receiver.GetStream());
        await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
        {
            ServerCertificate = certificate,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
        }, cancellationToken);
        Assert.True(ssl.IsEncrypted);
        return await ReadTcpPayloadAsync(ssl, "octet", cancellationToken);
    }

    private static X509Certificate2 CreateUntrustedCertificate()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=synthetic-syslog.test", key, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var name = new SubjectAlternativeNameBuilder();
        name.AddDnsName("synthetic-syslog.test");
        request.CertificateExtensions.Add(name.Build());
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-3), DateTimeOffset.UtcNow.AddDays(-1));
    }

    private static async Task<byte[]> ReadTcpPayloadAsync(Stream stream, string framing, CancellationToken cancellationToken)
    {
        if (framing == "lf")
            return await ReadUntilAsync(stream, (byte)'\n', cancellationToken);

        var prefix = await ReadUntilAsync(stream, (byte)' ', cancellationToken);
        var length = int.Parse(Encoding.ASCII.GetString(prefix), CultureInfo.InvariantCulture);
        Assert.InRange(length, 1, 8192);
        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload.AsMemory(), cancellationToken);
        return payload;
    }

    private static async Task<byte[]> ReadUntilAsync(Stream stream, byte separator, CancellationToken cancellationToken)
    {
        var buffer = new List<byte>();
        var next = new byte[1];
        while (buffer.Count <= 8192)
        {
            await stream.ReadExactlyAsync(next.AsMemory(), cancellationToken);
            if (next[0] == separator)
                return [.. buffer];
            buffer.Add(next[0]);
        }

        throw new InvalidDataException("合成接收器未在限定长度内读到分隔符。");
    }

    private static JsonDocument ReadBody(byte[] payload)
    {
        var start = payload.AsSpan().IndexOf("\uFEFF"u8);
        Assert.True(start > 0);
        return JsonDocument.Parse(payload.AsMemory(start + 3));
    }

    private static string ReadHostname(byte[] payload) => Encoding.UTF8.GetString(payload).Split(' ', 4)[2];

    private static CancellationTokenSource TestTimeout() => new(TimeSpan.FromSeconds(10));

    private static TcpListener StartTcp()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return listener;
    }

    private static int Port(TcpListener listener) => ((IPEndPoint)listener.LocalEndpoint).Port;

    private static SyslogTarget Target(int port, string protocol) =>
        new("synthetic", "test", "合成接收器", "127.0.0.1", port, protocol);
}
