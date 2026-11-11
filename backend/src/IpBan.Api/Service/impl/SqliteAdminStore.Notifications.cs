using Microsoft.Data.Sqlite;

namespace IpBan.Api.Service.impl;

public sealed partial class SqliteAdminStore
{
    internal Task<SqliteConnection> OpenNotificationConnectionAsync(CancellationToken cancellationToken) => OpenAsync(cancellationToken);

    internal static Task AppendNotificationAuditAsync(SqliteConnection connection, SqliteTransaction transaction,
        string action, string target, string actor, string? remoteIp, CancellationToken cancellationToken) =>
        AppendAuditCoreAsync(connection, transaction, action, "notifications", target, null, remoteIp, true, actor, cancellationToken);
}
