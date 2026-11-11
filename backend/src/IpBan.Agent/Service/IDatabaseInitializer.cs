namespace IpBan.Agent.Service;

public interface IDatabaseInitializer
{
    string DatabasePath { get; }

    Task<DatabaseInitializationResult> InitializeAsync(CancellationToken cancellationToken = default);
}

public sealed record DatabaseInitializationResult(
    string DatabasePath,
    int PreviousVersion,
    int CurrentVersion,
    bool DatabaseCreated,
    string? BackupPath);
