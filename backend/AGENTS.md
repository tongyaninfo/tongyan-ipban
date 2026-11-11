# 后端开发规则

本文件补充根 AGENTS.md，适用于 backend/。一期方案以 docs/spec/一期实施方案.md 为准。

## 工程结构

- 项目保持单向依赖：IpBan.Api → IpBan.Shared；IpBan.Agent → IpBan.Engine、IpBan.Shared；IpBan.Engine → IpBan.Shared。
- IpBan.Engine 不得引用 ASP.NET Core、宿主类型、系统命令或环境配置。
- IpBan.Agent 负责高权限日志采集、auditd/eBPF/WFP/ETW 关联、SQLite、防火墙 provider、当前会话和后台任务。
- IpBan.Api 负责 HTTPS 管理 API、认证、配置、导出、备份、当前连接查询和 wwwroot。
- Api 与 Agent 通过本机 Unix Domain Socket 或 Windows Named Pipe 通信。
- 依赖版本集中管理（`Directory.Packages.props`）；解决方案入口为 `IpBan.slnx`，Shared、Engine、Agent、Api 四个项目和对应测试项目均已建立。

## 登录事件和判定

- 统一事件包含协议、成功/失败、用户名、远端 IP/端口、本地 IP/端口、服务进程、回环发起进程、证据来源和完整性等级。
- 事件分为 Full、IpEnforceable、ObserveOnly。只要远端 IP 可靠，允许 IpEnforceable 事件参与 IP 级别 Ban。
- 字段缺失使用 NotProvided、NotCollected、CorrelationFailed 或 NotApplicable，不伪造 Unknown。
- Windows 支持 RDP、OpenSSH、WinRM；Linux 支持 SSH 和具体 VNC 实现适配器。
- 判定输入为归一化来源、名单快照、策略版本和观测窗口，输出命中列表和动作，保持确定性。
- 白名单和例外优先；自动策略必须有阈值、窗口、观察期、冷却期、封禁时长和版本。
- 已建立会话默认不因普通 Ban 自动断开，人工断开作为独立操作。

## 防火墙

- 一期支持 Windows Defender Firewall/WFP、firewalld、ufw、nftables、iptables。
- Provider 接口包括 Detect、GetCapabilities、Ban、Unban、HealthCheck。
- 只选择一个活动 provider，使用 IPBan 专属规则集合，操作幂等，不覆盖用户已有规则。
- 防火墙关闭或失败时记录 Disabled/Failed 和 ProtectionDegraded，继续采集和生成 BanDecision。
- 不提供一键恢复、自动恢复、规则对账、历史补写、自动重试队列或恢复动作审计。
- 防火墙恢复后旧失败动作不自动下发；新动作按正常流程执行。
- 开发和测试中的真实防火墙操作只能在用户明确批准的隔离主机执行。

## 存储和后台任务

- SQLite 使用 WAL、单实例迁移锁、事务和迁移历史。
- 服务启动自动创建数据库并执行正向、非破坏性迁移；迁移前备份；迁移失败时不启动采集和防火墙。
- 业务 ID 使用 IIdService/YiteIdService；双进程不得共用同一 WorkerId。
- 登录事件保留 365 天；支持轮转、压缩、导出、备份和大小指标。
- 审计和普通日志分开；审计不可用时管理写操作不得报告成功。
- 后台任务必须可取消、可观测、可重入，不无限重试。

## 接口与安全

- 业务接口统一 ApiResult<T> 和真实 HTTP 状态码。
- 管理台默认 HTTPS 监听 0.0.0.0；IPv6 不默认绑定。
- 多用户同权，不做 RBAC；所有账号仍需认证和操作审计。
- 敏感操作需要重新认证或二次确认；错误不得泄露密钥、连接串、堆栈和内部地址。
- 导入限制大小、类型和解析时间，不执行导入内容中的命令。
- MCP 服务作为可选扩展实现，默认停止；启用需管理员显式操作并创建受限 API Key，按工具授权、可吊销、调用留痕，不开放未定义写操作。

## 验证

- 初始化后运行 dotnet build、dotnet test 和 Native AOT publish smoke test。
- 测试覆盖 Full/IpEnforceable/ObserveOnly、SSH/RDP/VNC/OpenSSH/WinRM、回环进程、当前连接、会话断开、防火墙失败、迁移和日志留存。
- 传感器和防火墙验证使用合成来源和获准隔离主机，不使用共享或生产环境。

