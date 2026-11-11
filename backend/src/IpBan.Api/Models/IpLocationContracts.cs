using System.Text.Json.Serialization;
using IpBan.Shared.Models;

namespace IpBan.Api.Models;

/// <summary>解析配置按整份快照保存；默认关闭，读取默认值不会写入数据库。</summary>
public sealed record IpLocationSettings(
    bool Enabled = false,
    string Protocol = "https",
    string Host = "ip.tongyaninfo.com",
    int Port = 443,
    string Database = "CZ88",
    double TimeoutSeconds = 2);

public sealed record IpLocationLookupRequest(string[] Ips);

public sealed record IpLocationBatchResult(bool Enabled, string Revision, IpLocationResult[] Items);

public sealed record IpLocationResult(
    string Ip,
    string Status,
    string? Country = null,
    string? Province = null,
    string? City = null,
    string? District = null,
    string? Region = null,
    string? Isp = null,
    string? Asn = null,
    string? AsName = null,
    string? Database = null,
    string? Version = null,
    string? Attribution = null,
    string? LicenseUrl = null);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(IpLocationSettings))]
[JsonSerializable(typeof(IpLocationLookupRequest))]
[JsonSerializable(typeof(ApiResult<IpLocationSettings>))]
[JsonSerializable(typeof(ApiResult<IpLocationBatchResult>))]
public sealed partial class IpLocationJsonContext : JsonSerializerContext;
