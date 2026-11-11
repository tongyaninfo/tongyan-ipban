using IpBan.Agent.Options;
using IpBan.Agent.Service.impl;
using Microsoft.Extensions.DependencyInjection;

namespace IpBan.Agent.Service;

public static class IpcServiceCollectionExtensions
{
    /// <summary>
    /// 注册平台当前连接查询、已有连接断开和本机 IPC 服务。
    /// </summary>
    public static IServiceCollection AddIpBanAgentIpc(this IServiceCollection services)
    {
        services.AddOptions<AgentIpcOptions>()
            .BindConfiguration(AgentIpcOptions.SectionName)
            .Validate(options => OperatingSystem.IsWindows()
                || !string.IsNullOrWhiteSpace(options.SocketPath),
                "AgentIpc:SocketPath 不能为空。")
            .Validate(options => !OperatingSystem.IsWindows()
                || !string.IsNullOrWhiteSpace(options.PipeName),
                "AgentIpc:PipeName 不能为空。")
            .ValidateOnStart();
        if (OperatingSystem.IsWindows())
        {
            services.AddSingleton<IConnectionSnapshotProvider, WindowsConnectionSnapshotProvider>();
            services.AddSingleton<IConnectionTerminator, WindowsConnectionTerminator>();
        }
        else
        {
            services.AddSingleton<IConnectionSnapshotProvider, LinuxConnectionSnapshotProvider>();
            services.AddSingleton<IConnectionTerminator, LinuxConnectionTerminator>();
        }

        services.AddHostedService<UnixDomainSocketAgentServer>();
        return services;
    }
}
