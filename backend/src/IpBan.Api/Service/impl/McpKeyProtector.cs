using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace IpBan.Api.Service.impl;

/// <summary>加密副本只用于管理员重新复制接入指令。认证只需要 Key 摘要。</summary>
public sealed class McpKeyProtector(SqliteAdminStore adminStore)
{
    private const int MasterKeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const UnixFileMode PrivateFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private readonly string _masterKeyPath = Path.Combine(Path.GetDirectoryName(adminStore.DatabasePath)!, "mcp-key-protection.bin");

    public byte[] Protect(long keyId, string secret, bool allowCreateMasterKey)
    {
        var key = ReadMasterKey(allowCreateMasterKey);
        var plaintext = Encoding.UTF8.GetBytes(secret);
        try
        {
            var payload = new byte[NonceSize + TagSize + plaintext.Length];
            var nonce = payload.AsSpan(0, NonceSize);
            RandomNumberGenerator.Fill(nonce);
            using var cipher = new AesGcm(key, TagSize);
            cipher.Encrypt(nonce, plaintext, payload.AsSpan(NonceSize + TagSize), payload.AsSpan(NonceSize, TagSize), AssociatedData(keyId));
            return payload;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public string Unprotect(long keyId, byte[] payload)
    {
        if (payload.Length <= NonceSize + TagSize)
        {
            throw new CryptographicException("MCP Key 的加密副本无效。");
        }

        var key = ReadMasterKey(allowCreate: false);
        var plaintext = new byte[payload.Length - NonceSize - TagSize];
        try
        {
            using var cipher = new AesGcm(key, TagSize);
            cipher.Decrypt(payload.AsSpan(0, NonceSize), payload.AsSpan(NonceSize + TagSize), payload.AsSpan(NonceSize, TagSize), plaintext, AssociatedData(keyId));
            return Encoding.UTF8.GetString(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private byte[] ReadMasterKey(bool allowCreate)
    {
        // 密钥材料和 SQLite 独立保存。已有密文时禁止自动更换丢失的密钥。
        if (allowCreate && !File.Exists(_masterKeyPath))
        {
            var key = RandomNumberGenerator.GetBytes(MasterKeySize);
            var stagingPath = $"{_masterKeyPath}.{Guid.NewGuid():N}.new";
            try
            {
                using (var stream = OperatingSystem.IsWindows() ? CreateWindowsKeyFile(stagingPath) : CreateUnixKeyFile(stagingPath))
                {
                    stream.Write(key);
                    stream.Flush(flushToDisk: true);
                }
                // 先写完整密钥再原子发布，崩溃不会留下半写入的正式密钥。
                File.Move(stagingPath, _masterKeyPath);
                return key;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(key);
                throw;
            }
        }

        using var source = File.OpenRead(_masterKeyPath);
        if (OperatingSystem.IsWindows())
        {
            CheckWindowsPermissions();
        }
        else if ((File.GetUnixFileMode(_masterKeyPath) & ~PrivateFileMode) != 0)
        {
            throw new UnauthorizedAccessException("MCP 加密密钥文件只允许当前服务账号访问。");
        }

        if (source.Length != MasterKeySize)
        {
            throw new CryptographicException("MCP 加密密钥文件长度无效。");
        }
        var result = new byte[MasterKeySize];
        source.ReadExactly(result);
        return result;
    }

    [UnsupportedOSPlatform("windows")]
    private static FileStream CreateUnixKeyFile(string path) => new(path, new FileStreamOptions
    {
        Mode = FileMode.CreateNew,
        Access = FileAccess.Write,
        Share = FileShare.None,
        UnixCreateMode = PrivateFileMode
    });

    [SupportedOSPlatform("windows")]
    private static FileStream CreateWindowsKeyFile(string path)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var owner = identity.User ?? throw new UnauthorizedAccessException("无法识别 MCP 服务账号。");
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl, AccessControlType.Allow));
        return new FileInfo(path).Create(FileMode.CreateNew, FileSystemRights.FullControl, FileShare.None, 4096, FileOptions.None, security);
    }

    [SupportedOSPlatform("windows")]
    private void CheckWindowsPermissions()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var security = new FileInfo(_masterKeyPath).GetAccessControl(AccessControlSections.Access);
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow && !rule.IdentityReference.Equals(identity.User))
            {
                throw new UnauthorizedAccessException("MCP 加密密钥文件只允许当前服务账号访问。");
            }
        }
    }

    private static byte[] AssociatedData(long keyId)
    {
        var bytes = new byte[sizeof(long)];
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(bytes, keyId);
        return bytes;
    }
}
