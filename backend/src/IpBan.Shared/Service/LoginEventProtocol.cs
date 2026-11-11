using IpBan.Shared.Models;

namespace IpBan.Shared.Service;

/// <summary>
/// 在读取历史登录事件时，根据已保存的 Windows 安全日志证据解释协议。
/// </summary>
public static class LoginEventProtocol
{
    public static string ResolveStored(string protocol, string? evidenceSource, string? localProcessName)
    {
        // 旧采集器把无法识别的 Security 4624/4625 记为 SSH。只纠正有明确来源的历史记录。
        if ((protocol.Equals(nameof(ProtocolKind.Ssh), StringComparison.OrdinalIgnoreCase) || protocol == "0")
            && (string.Equals(evidenceSource, "eventlog:Security:4624", StringComparison.OrdinalIgnoreCase)
                || string.Equals(evidenceSource, "eventlog:Security:4625", StringComparison.OrdinalIgnoreCase))
            && !IsOpenSshProcess(localProcessName))
        {
            return nameof(ProtocolKind.Unidentified);
        }

        return protocol;
    }

    public static bool IsOpenSshProcess(string? processName)
    {
        if (processName is null)
        {
            return false;
        }

        var executable = processName.AsSpan(processName.LastIndexOfAny(['\\', '/']) + 1);
        if (executable.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            executable = executable[..^4];
        }

        return executable.Equals("sshd", StringComparison.OrdinalIgnoreCase)
            || executable.Equals("sshd-session", StringComparison.OrdinalIgnoreCase)
            || executable.Equals("sshd-auth", StringComparison.OrdinalIgnoreCase);
    }
}
