using System.Text.Json.Serialization;
using IpBan.Shared.Models;
using IpBan.Shared.Logging;

namespace IpBan.Shared.Serialization;

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(ApiResult<SystemStatusContract>))]
[JsonSerializable(typeof(ApiResult<string>))]
[JsonSerializable(typeof(ApiResult<OverviewContract>))]
[JsonSerializable(typeof(ApiResult<UserSummaryContract[]>))]
[JsonSerializable(typeof(ApiResult<UserSummaryContract>))]
[JsonSerializable(typeof(ApiResult<SetupStatusContract>))]
[JsonSerializable(typeof(ApiResult<SystemSettingContract[]>))]
[JsonSerializable(typeof(ApiResult<CertificateMetadataContract[]>))]
[JsonSerializable(typeof(ApiResult<AuditRecordContract[]>))]
[JsonSerializable(typeof(ApiResult<BackupRecordContract[]>))]
[JsonSerializable(typeof(ApiResult<FirewallActionContract[]>))]
[JsonSerializable(typeof(ApiResult<FileLogFileInfo[]>))]
[JsonSerializable(typeof(ApiResult<string[]>))]
[JsonSerializable(typeof(ApiResult<CurrentUserContract>))]
[JsonSerializable(typeof(LoginResponseContract))]
[JsonSerializable(typeof(ApiResult<ConnectionSnapshotContract[]>))]
[JsonSerializable(typeof(ApiResult<LoginSessionContract[]>))]
[JsonSerializable(typeof(ApiResult<LoginEventContract[]>))]
[JsonSerializable(typeof(LoginEventContract))]
[JsonSerializable(typeof(AgentIpcRequest))]
[JsonSerializable(typeof(AgentIpcResponse))]
[JsonSerializable(typeof(ApiResult<ConnectionTerminationContract>))]
[JsonSerializable(typeof(ConnectionTerminationContract))]
[JsonSerializable(typeof(ManualBanResult))]
[JsonSerializable(typeof(FirewallActionResult))]
[JsonSerializable(typeof(FirewallObservation))]
[JsonSerializable(typeof(ApiResult<ManualBanResult>))]
[JsonSerializable(typeof(ApiResult<FirewallActionResult>))]
public partial class IpBanJsonContext : JsonSerializerContext
{
}
