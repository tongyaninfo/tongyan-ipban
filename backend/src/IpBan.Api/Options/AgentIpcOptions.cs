namespace IpBan.Api.Options;

/// <summary>
/// API 访问本机 Agent Unix Socket 的配置。相对路径以 API ContentRoot 为基准。
/// </summary>
public sealed class AgentIpcOptions
{
    public const string SectionName = "AgentIpc";

    public string SocketPath { get; set; } = "run/ipban-agent.sock";

    /// <summary>Windows Named Pipe 名称；不包含 \\.\pipe\ 前缀。</summary>
    public string PipeName { get; set; } = "ipban-agent";
}
