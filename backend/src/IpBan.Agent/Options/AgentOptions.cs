namespace IpBan.Agent.Options;

public sealed class AgentOptions
{
    public const string SectionName = "Agent";

    public string DataDirectory { get; set; } = "data";

    public string DatabaseFileName { get; set; } = "ipban.sqlite3";

    public bool StrictEventCompleteness { get; set; }
}
