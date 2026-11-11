using IpBan.Shared.Models;

namespace IpBan.Agent.Models;

/// <summary>数据库动作序号同时作为封禁代次，防止旧到期任务解除后续新封禁。</summary>
public sealed record RecordedFirewallAction(long Id, FirewallActionResult Result);
