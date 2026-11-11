namespace IpBan.Api.Options;

public sealed class ManagementDataOptions
{
    public const string SectionName = "Agent";

    public string DataDirectory { get; set; } = "data";
    public string DatabaseFileName { get; set; } = "ipban.sqlite3";
    public string LogDirectory { get; set; } = "logs";
    public string BackupDirectory { get; set; } = "backups";
}
