namespace IpBan.Agent.Options;

/// <summary>
/// Linux SSH journald 采集器参数。参数只控制只读日志查询，不包含防火墙动作。
/// </summary>
public sealed class LinuxSshCollectorOptions
{
    public const string SectionName = "Collectors:LinuxSsh";

    public bool Enabled { get; set; } = true;

    public string Unit { get; set; } = "sshd.service";

    public int MaxLines { get; set; } = 1000;
}
