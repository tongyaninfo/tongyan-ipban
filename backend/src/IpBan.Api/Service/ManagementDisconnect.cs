using IpBan.Api.Service.impl;
using IpBan.Shared.Models;

namespace IpBan.Api.Service;

internal static class ManagementDisconnect
{
    public static async Task<ApiResult<ConnectionTerminationContract>> RunAsync(HttpContext context, SqliteAdminStore store,
        IAgentIpcClient client, ConnectionSnapshotContract connection, CancellationToken cancellationToken)
    {
        var actor = context.Items["ipban.user"] as string;
        var remoteIp = context.Connection.RemoteIpAddress?.ToString();
        var target = connection.RemoteIp;
        await store.AppendAuditAsync("session.disconnect.request", "session", target, null, remoteIp, true,
            actor, context.TraceIdentifier, result: "requested", cancellationToken: cancellationToken).ConfigureAwait(false);
        var result = await client.DisconnectAsync(connection, cancellationToken).ConfigureAwait(false);
        await store.AppendAuditAsync("session.disconnect", "session", target, null, remoteIp,
            result.Success && result.Data?.Success == true, actor, context.TraceIdentifier,
            result: result.Code, cancellationToken: CancellationToken.None).ConfigureAwait(false);
        return result;
    }
}
