using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using IpBan.Api.Options;

namespace IpBan.Api.Service.impl;

/// <summary>
/// 管理台 HTTPS 证书的运行时解析。首启自动生成一张本机自签名证书，上传证书后下次重启读取固定路径。
/// </summary>
public static class CertificateRuntime
{
    public const string ActiveFileName = "https-active.pfx";

    public static string ResolveActivePath(IConfiguration configuration, string contentRoot)
    {
        var dataDirectory = configuration["Agent:DataDirectory"];
        var resolvedDataDirectory = string.IsNullOrWhiteSpace(dataDirectory)
            ? Path.Combine(contentRoot, "data")
            : Path.GetFullPath(dataDirectory, contentRoot);
        var certificateDirectory = Path.Combine(resolvedDataDirectory, "certificates");
        Directory.CreateDirectory(certificateDirectory);
        return Path.Combine(certificateDirectory, ActiveFileName);
    }

    public static string EnsureSelfSignedCertificate(IConfiguration configuration, string contentRoot)
    {
        var path = ResolveActivePath(configuration, contentRoot);
        if (File.Exists(path))
        {
            return path;
        }

        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=通研 IPBan 管理台",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        san.AddIpAddress(IPAddress.Loopback);
        san.AddIpAddress(IPAddress.IPv6Loopback);
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid("1.3.6.1.5.5.7.3.1")],
            false));

        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(2));
        File.WriteAllBytes(path, certificate.Export(X509ContentType.Pkcs12));
        TryRestrictFile(path);
        return path;
    }

    public static X509Certificate2 Load(string path)
    {
        var bytes = File.ReadAllBytes(path);
        var keyStorageFlags = OperatingSystem.IsWindows()
            ? X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet
            : X509KeyStorageFlags.EphemeralKeySet;
        return X509CertificateLoader.LoadPkcs12(bytes, string.Empty, keyStorageFlags);
    }

    private static void TryRestrictFile(string path)
    {
        try
        {
            if (OperatingSystem.IsLinux())
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
        catch (PlatformNotSupportedException)
        {
            // Windows 使用安装目录 ACL 控制证书文件访问。
        }
    }
}
