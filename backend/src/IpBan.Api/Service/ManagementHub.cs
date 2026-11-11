using IpBan.Api.Service.impl;
using Microsoft.AspNetCore.SignalR;

namespace IpBan.Api.Service;

/// <summary>
/// 管理台实时刷新 Hub。连接必须携带当前管理会话 Cookie，或通过 access_token 查询参数传入同一个会话 Token。
/// </summary>
public sealed partial class ManagementHub(
    SqliteAdminStore store,
    ILogger<ManagementHub> logger) : Hub
{
    public const string Path = "/hubs/management";
    public const string DataChangedEvent = "dataChanged";

    private static readonly HashSet<string> AllowedChannels = new(StringComparer.OrdinalIgnoreCase)
    {
        "overview",
        "connections",
        "security-events"
    };

    public override async Task OnConnectedAsync()
    {
        var token = ReadSessionToken(Context.GetHttpContext());
        var user = string.IsNullOrWhiteSpace(token)
            ? null
            : await store.GetUserBySessionAsync(UserPasswordHasher.HashToken(token), Context.ConnectionAborted).ConfigureAwait(false);
        if (user is null)
        {
            LogUnauthorizedConnection(Context.ConnectionId);
            Context.Abort();
            return;
        }

        Context.Items["ipban.user"] = user.Username;
        await base.OnConnectedAsync().ConfigureAwait(false);
    }

    public async Task Subscribe(string channel)
    {
        EnsureAllowedChannel(channel);
        await Groups.AddToGroupAsync(Context.ConnectionId, GroupName(channel), Context.ConnectionAborted).ConfigureAwait(false);
    }

    public async Task Unsubscribe(string channel)
    {
        EnsureAllowedChannel(channel);
        await Groups.RemoveFromGroupAsync(Context.ConnectionId, GroupName(channel), Context.ConnectionAborted).ConfigureAwait(false);
    }

    internal static string GroupName(string channel) => $"ipban:{channel.ToLowerInvariant()}";

    internal static string? ReadSessionToken(HttpContext? httpContext)
    {
        if (httpContext is null)
        {
            return null;
        }

        if (httpContext.Request.Cookies.TryGetValue("ipban.session", out var cookieToken)
            && !string.IsNullOrWhiteSpace(cookieToken))
        {
            return cookieToken;
        }

        return httpContext.Request.Query.TryGetValue("access_token", out var queryToken)
            ? queryToken.ToString()
            : null;
    }

    private static void EnsureAllowedChannel(string channel)
    {
        if (!AllowedChannels.Contains(channel))
        {
            throw new HubException("不支持的实时订阅频道。");
        }
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "拒绝未授权的 SignalR 管理台连接 {ConnectionId}。")]
    private partial void LogUnauthorizedConnection(string connectionId);
}

public sealed record ManagementRealtimeEvent(string Channel, DateTimeOffset AtUtc);
