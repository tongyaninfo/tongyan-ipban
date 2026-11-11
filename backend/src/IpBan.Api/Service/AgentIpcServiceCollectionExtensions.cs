using IpBan.Api.Options;
using IpBan.Api.Service.impl;
using Microsoft.Extensions.DependencyInjection;

namespace IpBan.Api.Service;

public static class AgentIpcServiceCollectionExtensions
{
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
        services.AddSingleton<IAgentIpcClient, UnixDomainSocketAgentClient>();
        return services;
    }
}
