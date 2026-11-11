namespace IpBan.Api.Models;

public sealed record ManagementAuditContext(string? Actor, string? RemoteIp, string? TraceId)
{
    public static ManagementAuditContext From(HttpContext context) => new(context.Items["ipban.user"] as string,
        context.Connection.RemoteIpAddress?.ToString(), context.TraceIdentifier);
}
