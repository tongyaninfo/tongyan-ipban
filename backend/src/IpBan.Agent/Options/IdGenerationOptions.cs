using Yitter.IdGenerator;

namespace IpBan.Agent.Options;

public sealed class IdGenerationOptions
{
    public const string SectionName = "IdGeneration";
    public const byte WorkerIdBitLength = 6;
    public const byte SequenceBitLength = 6;
    public const int MaxWorkerId = (1 << WorkerIdBitLength) - 1;

    /// <summary>
    /// Agent 进程必须显式配置 WorkerId，避免多个进程静默使用同一节点号。
    /// </summary>
    public int? WorkerId { get; set; }

    public IdGeneratorOptions CreateGeneratorOptions()
    {
        if (WorkerId is null)
        {
            throw new InvalidOperationException("缺少 IdGeneration:WorkerId 配置。");
        }

        if (WorkerId is < 0 or > MaxWorkerId)
        {
            throw new InvalidOperationException(
                $"IdGeneration:WorkerId 必须介于 0 和 {MaxWorkerId} 之间。");
        }

        return new IdGeneratorOptions((ushort)WorkerId.Value)
        {
            WorkerIdBitLength = WorkerIdBitLength,
            SeqBitLength = SequenceBitLength
        };
    }
}
