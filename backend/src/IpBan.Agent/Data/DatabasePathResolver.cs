using IpBan.Agent.Options;

namespace IpBan.Agent.Data;

/// <summary>
/// 统一解析 Agent 的数据目录，避免 API、后台任务和测试各自拼接数据库路径。
/// </summary>
public static class DatabasePathResolver
{
    public static string Resolve(AgentOptions options, string contentRootPath)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(contentRootPath);

        if (string.IsNullOrWhiteSpace(options.DatabaseFileName))
        {
            throw new InvalidOperationException("Agent:DatabaseFileName 不能为空。");
        }

        var dataDirectory = Path.IsPathRooted(options.DataDirectory)
            ? options.DataDirectory
            : Path.Combine(contentRootPath, options.DataDirectory);

        return Path.Combine(dataDirectory, options.DatabaseFileName);
    }
}
