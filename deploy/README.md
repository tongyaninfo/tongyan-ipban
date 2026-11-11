# 部署

本目录当前只有规划说明与 Docker 部署约束，不含 Dockerfile、Compose、systemd unit、配置示例或部署脚本。后端、前端与内嵌 SQLite 已实现；发布制品与真实主机部署验收仍待完成。

部署配置中的主机、地址与访问方式使用占位符，不写真实主机、账号、口令或私钥。部署、开放端口、防火墙操作、服务重启和数据卷变更必须针对具体环境取得授权。

## 单机部署形态

| 组件 | 规划 |
| --- | --- |
| IpBan.Api | HTTPS 管理台和 API，默认监听 0.0.0.0，IPv6 不默认绑定 |
| IpBan.Agent | 高权限日志采集、连接关联、SQLite、防火墙和当前会话 |
| 通信 | Api 与 Agent 使用本机 Unix Domain Socket 或 Windows Named Pipe |
| 存储 | SQLite 单实例、WAL、启动自动创建和正向迁移 |
| Windows | Windows Service |
| Linux | systemd |
| 前端 | 构建后复制到 Api 的 wwwroot |

## 防火墙和网络边界

一期支持 Windows Defender Firewall/WFP、firewalld、ufw、nftables、iptables。Provider 负责 Detect、Ban、Unban 和 HealthCheck。

防火墙关闭时只记录 Disabled/Failed 和 ProtectionDegraded。部署不提供自动恢复、一键恢复、规则对账、历史补写、自动重试或恢复动作审计。旧的失败动作不自动下发。

管理台绑定 0.0.0.0 代表所有 IPv4 网卡可能访问，必须使用 HTTPS、账号认证、登录限速、CSRF 和安全 Cookie。系统不自动替用户放行管理端口，端口放行和网络访问范围由运维按环境单独确认。

## 启动和升级

首次启动自动创建 SQLite 并执行正向、非破坏性迁移。迁移使用锁、事务和历史记录，迁移前备份；迁移失败时不启动 Agent 和防火墙执行。

升级前备份数据库和配置。破坏性迁移、数据删除和服务恢复不由普通启动隐式执行。

## 当前状态

当前没有已部署实例、镜像、部署脚本或服务单元。本文只描述部署约束和顺序，不能作为已上线或已验收依据。

