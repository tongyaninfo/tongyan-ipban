using System.Globalization;
using IpBan.Shared.Service;
using Yitter.IdGenerator;

namespace IpBan.Api.Service.impl;

/// <summary>管理 API 进程使用独立 WorkerId 发放 MCP Key 和审计 ID。</summary>
public sealed class McpIdService(IConfiguration configuration) : IIdService
{
    private readonly DefaultIdGenerator generator = new(CreateOptions(configuration["Mcp:WorkerId"]));

    public long NewId => generator.NewLong();

    private static IdGeneratorOptions CreateOptions(string? configuredWorkerId)
    {
        const ushort defaultWorkerId = 2;
        var workerId = defaultWorkerId;
        if (configuredWorkerId is not null
            && (!ushort.TryParse(configuredWorkerId, NumberStyles.None, CultureInfo.InvariantCulture, out workerId) || workerId > 63))
        {
            throw new InvalidOperationException("Mcp:WorkerId 必须介于 0 和 63 之间，并且与 Agent 的 WorkerId 不同。");
        }

        return new IdGeneratorOptions(workerId) { WorkerIdBitLength = 6, SeqBitLength = 6 };
    }
}
