namespace IpBan.Agent.Options;

/// <summary>
/// Agent 本机 IPC 配置。相对路径以 Agent ContentRoot 为基准。
/// </summary>
public sealed class AgentIpcOptions
{
    public const string SectionName = "AgentIpc";

    public string SocketPath { get; set; } = "run/ipban-agent.sock";

    /// <summary>Windows Named Pipe 名称；不包含 \\.\pipe\ 前缀。</summary>
    public string PipeName { get; set; } = "ipban-agent";
}
