using IpBan.Agent.Service.impl;
using IpBan.Agent.Workers;
using IpBan.Agent.Options;
using IpBan.Shared.Service;
using Microsoft.Extensions.DependencyInjection;

namespace IpBan.Agent.Service;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddIpBanIdGeneration(this IServiceCollection services)
    {
        services.AddOptions<IdGenerationOptions>()
            .BindConfiguration(IdGenerationOptions.SectionName)
            .Validate(
                options => options.WorkerId is >= 0 and <= IdGenerationOptions.MaxWorkerId,
                $"IdGeneration:WorkerId 必须显式配置在 0 和 {IdGenerationOptions.MaxWorkerId} 之间。")
            .ValidateOnStart();
        services.AddSingleton<IIdService, YiteIdService>();
        services.AddHostedService<IdGenerationInitializationHostedService>();
        return services;
    }

    public static IServiceCollection AddIpBanPersistence(this IServiceCollection services)
    {
        services.AddOptions<LinuxSshCollectorOptions>()
            .BindConfiguration(LinuxSshCollectorOptions.SectionName)
            .Validate(
                options => !string.IsNullOrWhiteSpace(options.Unit),
                "Collectors:LinuxSsh:Unit 不能为空。")
            .Validate(
                options => options.MaxLines is >= 1 and <= 10000,
                "Collectors:LinuxSsh:MaxLines 必须在 1 到 10000 之间。")
            .ValidateOnStart();
        services.AddOptions<LinuxVncCollectorOptions>()
            .BindConfiguration(LinuxVncCollectorOptions.SectionName)
            .Validate(options => options.Source.Equals("Journal", StringComparison.OrdinalIgnoreCase)
                || options.Source.Equals("Files", StringComparison.OrdinalIgnoreCase),
                "Collectors:LinuxVnc:Source 必须为 Journal 或 Files。")
            .Validate(options => options.LookbackSeconds is >= 10 and <= 3600
                && options.MaxLines is >= 1 and <= 50000
                && options.MaxFileBytesPerPoll is >= 4096 and <= 4_194_304,
                "TigerVNC 回读窗口、日志行数或单次文件读取上限不合法。")
            .Validate(options => options.LogFiles.All(Path.IsPathFullyQualified)
                && options.JournalIdentifiers.All(identifier => !string.IsNullOrWhiteSpace(identifier)),
                "TigerVNC 日志文件必须使用绝对路径，journal 标识不能为空。")
            .ValidateOnStart();
        services.AddSingleton<IDatabaseInitializer, SqliteDatabaseInitializer>();
        services.AddSingleton<ISqliteConnectionFactory, SqliteConnectionFactory>();
        services.AddSingleton<ILoginEventStore, SqliteLoginEventStore>();
        services.AddSingleton<IFirewallActionStore, SqliteFirewallActionStore>();
        services.AddSingleton<FirewallActionCoordinator>();
        if (OperatingSystem.IsWindows())
        {
            // EventLog 仅在 Windows 注册，避免 Linux/AOT 分析器把 Windows 专用 API 视为跨平台调用。
            services.AddSingleton<ILoginEventCollector, WindowsEventLogLoginCollector>();
        }
        else if (OperatingSystem.IsLinux())
        {
            services.AddSingleton<ILoginEventCollector, LinuxSshLoginCollector>();
            services.AddSingleton<ILoginEventCollector, LinuxVncLoginCollector>();
        }
        services.AddHostedService<DatabaseInitializationHostedService>();
        services.AddHostedService<FirewallProviderDetectionHostedService>();
        services.AddHostedService<LoginEventCollectionHostedService>();
        services.AddHostedService<AutomaticBanHostedService>();
        return services;
    }

    public static IServiceCollection AddIpBanFirewallProviders(this IServiceCollection services)
    {
        services.AddSingleton<IFirewallCommandRunner, ProcessFirewallCommandRunner>();
        services.AddSingleton<IFirewallProvider, FirewalldFirewallProvider>();
        services.AddSingleton<IFirewallProvider, UfwFirewallProvider>();
        services.AddSingleton<IFirewallProvider, NftablesFirewallProvider>();
        services.AddSingleton<IFirewallProvider, IptablesFirewallProvider>();
        services.AddSingleton<IFirewallProvider, WindowsDefenderFirewallWfpProvider>();
        services.AddSingleton<IFirewallProviderSelector, FirewallProviderSelector>();
        return services;
    }
}
