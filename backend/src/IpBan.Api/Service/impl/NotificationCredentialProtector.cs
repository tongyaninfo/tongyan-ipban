using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace IpBan.Api.Service.impl;

/// <summary>SMTP 授权码与数据库分离保护；密钥丢失或权限扩大时拒绝解密，不静默生成替代密钥。</summary>
public sealed class NotificationCredentialProtector(SqliteAdminStore adminStore)
{
    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const UnixFileMode PrivateFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private static readonly byte[] Purpose = "IpBan.Notification.SmtpCredential:v1"u8.ToArray();
    private readonly object gate = new();
    private readonly string keyPath = Path.Combine(Path.GetDirectoryName(adminStore.DatabasePath)!, "notifications-key-protection.bin");

    public string Protect(string secret, bool allowCreateMasterKey = true)
    {
        ArgumentException.ThrowIfNullOrEmpty(secret);
        if (secret.Length > 4096) throw new ArgumentException("邮件授权码长度超出限制。", nameof(secret));
        var key = ReadKey(allowCreateMasterKey);
        var plaintext = Encoding.UTF8.GetBytes(secret);
        try
        {
            var payload = new byte[1 + NonceSize + TagSize + plaintext.Length];
            payload[0] = 1;
            var nonce = payload.AsSpan(1, NonceSize);
            RandomNumberGenerator.Fill(nonce);
            using var cipher = new AesGcm(key, TagSize);
            cipher.Encrypt(nonce, plaintext, payload.AsSpan(1 + NonceSize + TagSize), payload.AsSpan(1 + NonceSize, TagSize), Purpose);
            return Convert.ToBase64String(payload);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public string Unprotect(string protectedSecret)
    {
        byte[] payload;
        try { payload = Convert.FromBase64String(protectedSecret); }
        catch (FormatException) { throw new CryptographicException("邮件授权码的加密副本无效。"); }
        if (payload.Length <= 1 + NonceSize + TagSize || payload[0] != 1)
            throw new CryptographicException("邮件授权码的加密副本无效。");
        var key = ReadKey(allowCreate: false);
        var plaintext = new byte[payload.Length - 1 - NonceSize - TagSize];
        try
        {
            using var cipher = new AesGcm(key, TagSize);
            cipher.Decrypt(payload.AsSpan(1, NonceSize), payload.AsSpan(1 + NonceSize + TagSize),
                payload.AsSpan(1 + NonceSize, TagSize), plaintext, Purpose);
            return Encoding.UTF8.GetString(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private byte[] ReadKey(bool allowCreate)
    {
        lock (gate)
        {
            if (allowCreate && !File.Exists(keyPath))
            {
                Directory.CreateDirectory(Path.GetDirectoryName(keyPath)!);
                var key = RandomNumberGenerator.GetBytes(KeySize);
                var stagingPath = $"{keyPath}.{Guid.NewGuid():N}.new";
                try
                {
                    using (var stream = OperatingSystem.IsWindows() ? CreateWindowsFile(stagingPath) : CreateUnixFile(stagingPath))
                    {
                        stream.Write(key);
                        stream.Flush(flushToDisk: true);
                    }
                    // 先完整写入再原子发布；已有密文时调用方必须禁用首次创建。
                    File.Move(stagingPath, keyPath);
                    return key;
                }
                catch
                {
                    CryptographicOperations.ZeroMemory(key);
                    throw;
                }
            }

            if (new FileInfo(keyPath).LinkTarget is not null)
                throw new UnauthorizedAccessException("邮件凭据密钥不能使用符号链接。");
            using var source = File.OpenRead(keyPath);
            if (OperatingSystem.IsWindows()) CheckWindowsPermissions();
            else if ((File.GetUnixFileMode(keyPath) & ~PrivateFileMode) != 0)
                throw new UnauthorizedAccessException("邮件凭据密钥只允许当前服务账号访问。");
            if (source.Length != KeySize) throw new CryptographicException("邮件凭据密钥长度无效。");
            var result = new byte[KeySize];
            source.ReadExactly(result);
            return result;
        }
    }

    [UnsupportedOSPlatform("windows")]
    private static FileStream CreateUnixFile(string path) => new(path, new FileStreamOptions
    {
        Mode = FileMode.CreateNew,
        Access = FileAccess.Write,
        Share = FileShare.None,
        UnixCreateMode = PrivateFileMode
    });

    [SupportedOSPlatform("windows")]
    private static FileStream CreateWindowsFile(string path)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var owner = identity.User ?? throw new UnauthorizedAccessException("无法识别邮件服务账号。");
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl, AccessControlType.Allow));
        return new FileInfo(path).Create(FileMode.CreateNew, FileSystemRights.FullControl, FileShare.None, 4096, FileOptions.None, security);
    }

    [SupportedOSPlatform("windows")]
    private void CheckWindowsPermissions()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var security = new FileInfo(keyPath).GetAccessControl(AccessControlSections.Access);
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow && !rule.IdentityReference.Equals(identity.User))
                throw new UnauthorizedAccessException("邮件凭据密钥只允许当前服务账号访问。");
        }
    }
}
