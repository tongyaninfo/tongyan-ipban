namespace IpBan.Agent.Options;

/// <summary>
/// TigerVNC 认证日志。一个实例只选择一种来源，避免文件与 journald 镜像双计数。
/// </summary>
public sealed class LinuxVncCollectorOptions
{
    public const string SectionName = "Collectors:LinuxVnc";

    public bool Enabled { get; set; } = true;
    public string Source { get; set; } = "Journal";
    public string[] JournalIdentifiers { get; set; } = ["Xvnc", "Xtigervnc"];
    public string[] LogFiles { get; set; } = [];
    public int LookbackSeconds { get; set; } = 300;
    public int MaxLines { get; set; } = 10000;
    public int MaxFileBytesPerPoll { get; set; } = 1_048_576;
}
