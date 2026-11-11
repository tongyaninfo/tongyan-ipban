using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;

namespace IpBan.Shared.Logging.Syslog;

/// <summary>由单个目标工作器串行使用的 Syslog 连接。写入失败后由调用方按队列策略重试。</summary>
public sealed class SyslogTransport(SyslogTarget target) : IAsyncDisposable
{
    private static readonly byte[] LineFeed = [(byte)'\n'];
    private static readonly TimeSpan SendTimeout = TimeSpan.FromSeconds(10);
    private const int StreamMessageLimit = 8192;
    private const int MaxRelpResponseBytes = 8192;
    private const int MaxRelpTransaction = 999_999_999;

    private Socket? udp;
    private TcpClient? tcp;
    private Stream? stream;
    private int relpTransaction;
    private bool disposed;

    public bool LastSendTruncated { get; private set; }

    /// <returns>RELP 对端确认时为 true。其余协议发送成功时为 false。</returns>
    public async Task<bool> SendAsync(SyslogEvent entry, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        LastSendTruncated = false;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(SendTimeout);
        try
        {
            return target.Protocol switch
            {
                "udp" => await SendUdpAsync(entry, timeout.Token).ConfigureAwait(false),
                "tcp" or "tls" or "relp" => await SendStreamAsync(entry, timeout.Token).ConfigureAwait(false),
                _ => throw new InvalidOperationException("不支持该 Syslog 传输协议。"),
            };
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && timeout.IsCancellationRequested)
        {
            ResetConnection();
            throw new TimeoutException("Syslog 连接、握手或发送超时。");
        }
        catch
        {
            ResetConnection();
            throw;
        }
    }

    private async Task<bool> SendUdpAsync(SyslogEvent entry, CancellationToken cancellationToken)
    {
        var socket = udp ??= await ConnectUdpAsync(cancellationToken).ConfigureAwait(false);
        var address = ((IPEndPoint)socket.RemoteEndPoint!).Address;
        var limit = address.AddressFamily == AddressFamily.InterNetworkV6 && !address.IsIPv4MappedToIPv6 ? 1180 : 480;
        var payload = SyslogWire.Format(entry, limit, out var truncated);
        var bytesSent = await socket.SendAsync(payload.AsMemory(), SocketFlags.None, cancellationToken).ConfigureAwait(false);
        if (bytesSent != payload.Length)
            throw new IOException("Syslog UDP 数据报写入不完整。");

        LastSendTruncated = truncated;
        return false;
    }

    private async Task<Socket> ConnectUdpAsync(CancellationToken cancellationToken)
    {
        var addresses = await Dns.GetHostAddressesAsync(target.Host, cancellationToken).ConfigureAwait(false);
        SocketException? error = null;
        foreach (var address in addresses)
        {
            if (address.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
                continue;

            Socket? socket = null;
            try
            {
                socket = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                await socket.ConnectAsync(new IPEndPoint(address, target.Port), cancellationToken).ConfigureAwait(false);
                return socket;
            }
            catch (SocketException ex)
            {
                socket?.Dispose();
                error = ex;
            }
            catch
            {
                socket?.Dispose();
                throw;
            }
        }

        throw error ?? new SocketException((int)SocketError.HostNotFound);
    }

    private async Task<bool> SendStreamAsync(SyslogEvent entry, CancellationToken cancellationToken)
    {
        var connection = stream ?? await ConnectStreamAsync(cancellationToken).ConfigureAwait(false);
        var payload = SyslogWire.Format(entry, StreamMessageLimit, out var truncated);

        if (target.Protocol == "relp")
        {
            await RelpCommandAsync(connection, "syslog", payload, cancellationToken).ConfigureAwait(false);
            LastSendTruncated = truncated;
            return true;
        }

        if (target.Protocol == "tcp" && target.Framing == "lf")
        {
            // JSON 转义字段内的换行符，线上唯一 LF 是消息的分隔符。
            await connection.WriteAsync(payload.AsMemory(), cancellationToken).ConfigureAwait(false);
            await connection.WriteAsync(LineFeed.AsMemory(), cancellationToken).ConfigureAwait(false);
        }
        else
        {
            var prefix = Encoding.ASCII.GetBytes(payload.Length.ToString(CultureInfo.InvariantCulture) + " ");
            await connection.WriteAsync(prefix.AsMemory(), cancellationToken).ConfigureAwait(false);
            await connection.WriteAsync(payload.AsMemory(), cancellationToken).ConfigureAwait(false);
        }

        LastSendTruncated = truncated;
        return false;
    }

    private async Task<Stream> ConnectStreamAsync(CancellationToken cancellationToken)
    {
        tcp = new TcpClient { NoDelay = true };
        await tcp.ConnectAsync(target.Host, target.Port, cancellationToken).ConfigureAwait(false);
        stream = tcp.GetStream();

        if (target.Protocol == "tls")
        {
            var ssl = new SslStream(stream);
            stream = ssl;
            var options = new SslClientAuthenticationOptions
            {
                TargetHost = target.Host,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            };

            if (target.IgnoreSslErrors)
            {
                // 只放宽该目标的证书校验。未出示证书或 TLS 协商失败时连接仍会失败。
                options.RemoteCertificateValidationCallback = static (_, certificate, _, errors) =>
                    certificate is not null && (errors & SslPolicyErrors.RemoteCertificateNotAvailable) == 0;
            }

            await ssl.AuthenticateAsClientAsync(options, cancellationToken).ConfigureAwait(false);
        }
        else if (target.Protocol == "relp")
        {
            // 使用当前 librelp 支持的协议版本及 syslog 命令协商。
            relpTransaction = 0;
            var response = await RelpCommandAsync(stream, "open", "relp_version=0\ncommands=syslog"u8.ToArray(), cancellationToken)
                .ConfigureAwait(false);
            ValidateRelpOffers(response);
        }

        return stream;
    }

    private async Task<byte[]> RelpCommandAsync(Stream connection, string command, ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        relpTransaction = relpTransaction >= MaxRelpTransaction ? 1 : relpTransaction + 1;
        var header = Encoding.ASCII.GetBytes(FormattableString.Invariant($"{relpTransaction} {command} {payload.Length}"));
        var frame = new byte[header.Length + (payload.IsEmpty ? 1 : payload.Length + 2)];
        header.CopyTo(frame, 0);
        if (!payload.IsEmpty)
        {
            frame[header.Length] = (byte)' ';
            payload.CopyTo(frame.AsMemory(header.Length + 1));
        }

        frame[^1] = (byte)'\n';
        await connection.WriteAsync(frame.AsMemory(), cancellationToken).ConfigureAwait(false);

        var singleByte = new byte[1];
        var (transactionToken, transactionSeparator) = await ReadRelpTokenAsync(connection, singleByte, 9, cancellationToken).ConfigureAwait(false);
        var (commandToken, commandSeparator) = await ReadRelpTokenAsync(connection, singleByte, 32, cancellationToken).ConfigureAwait(false);
        var (lengthToken, lengthSeparator) = await ReadRelpTokenAsync(connection, singleByte, 9, cancellationToken).ConfigureAwait(false);

        if (transactionSeparator != ' ' || commandSeparator != ' '
            || !int.TryParse(transactionToken, NumberStyles.None, CultureInfo.InvariantCulture, out var transaction)
            || !int.TryParse(lengthToken, NumberStyles.None, CultureInfo.InvariantCulture, out var length)
            || length > MaxRelpResponseBytes || lengthSeparator != (length == 0 ? '\n' : ' '))
            throw new IOException("Syslog RELP 应答帧格式无效。");

        if (transaction == 0 && commandToken == "serverclose")
            throw new IOException("Syslog RELP 对端关闭了会话。");

        if (transaction != relpTransaction || commandToken != "rsp")
            throw new IOException("Syslog RELP 应答事务或命令不匹配。");

        // librelp 对 close 使用无正文应答。消息确认仍必须包含成功状态码。
        if (length == 0 && command == "close")
            return [];
        if (length < 3)
            throw new IOException("Syslog RELP 应答缺少状态码。");

        var response = new byte[length];
        await connection.ReadExactlyAsync(response.AsMemory(), cancellationToken).ConfigureAwait(false);
        await connection.ReadExactlyAsync(singleByte.AsMemory(), cancellationToken).ConfigureAwait(false);
        if (singleByte[0] != (byte)'\n')
            throw new IOException("Syslog RELP 应答缺少帧终止符。");

        if (!response.AsSpan().StartsWith("200"u8) || response.Length > 3 && response[3] is not ((byte)' ' or (byte)'\n'))
            throw new IOException("Syslog RELP 对端拒绝了事务。");

        return response;
    }

    private static async Task<(string Token, char Separator)> ReadRelpTokenAsync(Stream connection, byte[] singleByte,
        int maxLength, CancellationToken cancellationToken)
    {
        var token = new byte[maxLength];
        for (var i = 0; i <= maxLength; i++)
        {
            await connection.ReadExactlyAsync(singleByte.AsMemory(), cancellationToken).ConfigureAwait(false);
            var next = singleByte[0];
            if (i > 0 && next is (byte)' ' or (byte)'\n')
                return (Encoding.ASCII.GetString(token, 0, i), (char)next);

            if (i == maxLength || next is < (byte)'!' or > (byte)'~')
                break;
            token[i] = next;
        }

        throw new IOException("Syslog RELP 应答头部超长或含非法字符。");
    }

    private static void ValidateRelpOffers(byte[] response)
    {
        var offers = Encoding.ASCII.GetString(response).Split('\n', StringSplitOptions.TrimEntries);
        var supportsVersion = false;
        var supportsSyslog = false;
        foreach (var offer in offers.Skip(1))
        {
            if (offer == "relp_version=0")
                supportsVersion = true;
            else if (offer.StartsWith("commands=", StringComparison.Ordinal))
                supportsSyslog |= offer[9..].Split(',').Contains("syslog", StringComparer.Ordinal);
        }

        if (!supportsVersion || !supportsSyslog)
            throw new IOException("Syslog RELP 对端没有协商出兼容的版本和 syslog 命令。");
    }

    private void ResetConnection()
    {
        stream?.Dispose();
        tcp?.Dispose();
        udp?.Dispose();
        stream = null;
        tcp = null;
        udp = null;
    }

    public async ValueTask DisposeAsync()
    {
        if (disposed)
            return;
        disposed = true;

        try
        {
            if (stream is not null && target.Protocol == "relp")
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
                await RelpCommandAsync(stream, "close", ReadOnlyMemory<byte>.Empty, timeout.Token).ConfigureAwait(false);
            }
            else if (stream is SslStream ssl)
            {
                await ssl.ShutdownAsync().WaitAsync(TimeSpan.FromMilliseconds(250)).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or TimeoutException)
        {
            // 已发送的事务以各自应答为准，关闭握手失败仍释放连接。
        }
        finally
        {
            ResetConnection();
        }
    }
}
