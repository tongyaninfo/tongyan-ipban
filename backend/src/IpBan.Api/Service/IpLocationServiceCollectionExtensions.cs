using System.Net;
using IpBan.Api.Models;
using IpBan.Api.Service.impl;
using IpBan.Api.Workers;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace IpBan.Api.Service;

public static class IpLocationServiceCollectionExtensions
{
    public static IServiceCollection AddIpLocation(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.AddSingleton<IpLocationService>();
        services.AddSingleton<IIPLocation>(_ => new TongYanIPLocation(new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            MaxConnectionsPerServer = 2,
            PooledConnectionLifetime = TimeSpan.FromMinutes(10),
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
        }) { Timeout = Timeout.InfiniteTimeSpan }));
        services.AddHostedService<IpLocationWorker>();
        services.ConfigureHttpJsonOptions(options => options.SerializerOptions.TypeInfoResolverChain.Insert(0, IpLocationJsonContext.Default));
        return services;
    }
}
