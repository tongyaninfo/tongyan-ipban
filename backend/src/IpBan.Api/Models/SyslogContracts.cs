using System.Text.Json.Serialization;
using IpBan.Shared.Logging.Syslog;
using IpBan.Shared.Models;

namespace IpBan.Api.Models;

public sealed record SyslogTestRequest(string TargetId, string ConfigRevision);

public sealed record SyslogTestResult(string TestId, string TargetId, string Protocol, string Stage,
    string Message, DateTimeOffset CompletedAtUtc);

public sealed record SyslogStatusResult(string DesiredRevision, SyslogProcessStatus Api, SyslogProcessStatus? Agent,
    string? AgentErrorCode);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(SyslogTestRequest))]
[JsonSerializable(typeof(ApiResult<SyslogSettings>))]
[JsonSerializable(typeof(ApiResult<SyslogTestResult>))]
[JsonSerializable(typeof(ApiResult<SyslogStatusResult>))]
internal sealed partial class SyslogApiJsonContext : JsonSerializerContext;
