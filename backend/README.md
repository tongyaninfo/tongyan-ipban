# 后端

通研 IPBan 后端由管理 API、特权 Agent、纯函数判定引擎和公共合同组成。Agent 负责本机登录采集、连接关联、SQLite、防火墙和当前会话；Api 负责 HTTPS 管理面和前端静态文件。产品范围见[一期实施方案](../docs/spec/一期实施方案.md)。

## 当前状态

- Shared、Engine、Agent、Api 四个 .NET 10 项目和 `IpBan.slnx` 已建立。
- Engine/Agent 测试骨架已建立；本机 `dotnet build`、`dotnet test` 和 Api/Agent Native AOT 发布冒烟已通过；隔离 Linux 测试环境中的 self-contained Agent 已验证数据库创建和 firewalld 探测。
- 已提供公共合同、纯函数判定、事件归一化、SQLite 事件仓储、Linux SSH/TigerVNC 与 Windows EventLog 采集、IPC 和防火墙执行。各协议的真实主机验证结果分别记录，源码接入不代表全部场景已通过验收。
- 一期只支持 Windows/Linux 单机 Agent，不支持 macOS、中心管理端和 RBAC。MCP 服务作为可选扩展提供，默认停止，需要管理员显式启用并创建受限 API Key，调用进入审计。
- 防火墙 provider 规划支持 Windows Defender Firewall/WFP、firewalld、ufw、nftables、iptables。
- 防火墙关闭时只记录 Disabled/Failed 和 ProtectionDegraded，不提供恢复、规则对账、历史补写或恢复审计。
- SQLite 使用 WAL、迁移锁和事务，服务启动自动创建数据库并执行正向非破坏性迁移。
- 所有业务 ID 使用 IIdService/YiteIdService；双进程不得共用同一 WorkerId。
- 管理台 HTTPS 默认绑定 0.0.0.0，IPv6 不默认绑定。

## 工程结构

    backend/
    ├── src/
    │   ├── IpBan.Shared/   # ApiResult、DTO、枚举、IPC 合同
    │   ├── IpBan.Engine/   # 纯函数封禁判定
    │   ├── IpBan.Agent/    # 高权限采集、SQLite、防火墙、会话和后台任务
    │   └── IpBan.Api/      # HTTPS API、认证、配置和 wwwroot
    └── tests/
        ├── IpBan.Engine.Tests/
        ├── IpBan.Agent.Tests/
        └── IpBan.Api.Tests/

## 运行约定

1. 初始化顺序：Shared → Engine → Agent → Api。
2. Agent 通过 root、Administrator 或等价权限访问日志、连接传感器和防火墙。
3. Api 与 Agent 通过本机 Unix Domain Socket 或 Windows Named Pipe 通信。
4. SQLite 启动自动创建和迁移；只执行正向、可审计、非破坏性迁移；迁移失败时不启动采集和防火墙。
5. 事件按 Full、IpEnforceable、ObserveOnly 分级；只要有可靠远端 IP，允许执行 IP 级别 Ban。
6. 当前连接和当前登录会话使用独立查询页面；普通 Ban 默认只阻止新连接。
7. 测试数据库只放在测试输出目录，使用合成来源和隔离主机，不触碰共享数据。
8. 代码改动后按真实工程文件运行 `dotnet build`、`dotnet test` 和相应的 AOT publish smoke test。

## TigerVNC 登录采集

Linux Agent 注册 TigerVNC 采集器，认证成功和失败事件使用 `Vnc` 协议进入现有登录日志、ALL/VNC 策略和防火墙执行流程。当前适配 TigerVNC 的 Xvnc/Xtigervnc 日志格式，其他 VNC 服务需要各自的日志适配。

在 Agent 配置的 `Collectors` 中设置 `LinuxVnc`，默认启用 `Journal` 来源。日志写入 journald 时按 Xvnc/Xtigervnc 进程名和 `JournalIdentifiers` 查询。文件输出部署需改用 `Files`，例如：

```json
{
  "Collectors": {
    "LinuxVnc": {
      "Enabled": true,
      "Source": "Files",
      "JournalIdentifiers": ["Xvnc", "Xtigervnc"],
      "LogFiles": ["/var/log/tigervnc/*.log"],
      "LookbackSeconds": 300,
      "MaxLines": 10000,
      "MaxFileBytesPerPoll": 1048576
    }
  }
}
```

`LogFiles` 使用绝对路径，文件名支持通配符。选择 `Files` 且列表为空时，自动检查 `/root`、`/home` 下用户的 `.vnc/*.log`、`.local/state/tigervnc/*.log` 和 `/var/log/tigervnc/*.log`。每个 Agent 选择一种日志来源，避免 journal 与文件副本重复统计。

TigerVNC 需保留认证信息日志，建议日志级别至少为 30。失败以携带远端端点的 `Authentication failure` 为依据。成功以每次认证成功输出的 `Server default pixel format` 为依据，只有读到服务启动监听标记、且存在唯一没有交错的握手上下文时才关联来源。Agent 接入已经运行很久的服务、并发握手或读取大文件尾部时，成功事件可能缺少可靠来源，此时保留观察事件。连接建立、普通断开以及 TigerVNC 自身黑名单拒绝不算新的密码失败。

VncAuth 不提供用户名，事件保留“未提供”，可信远端 IP 仍可参与 IP 封禁。端点优先取原始日志，并通过活动连接补齐本地端点和进程。文件日期按服务器操作系统时区解释后转 UTC，界面按浏览器时区展示。

采集器保留有限时间的结果重放缓存，文件读取支持完整行、截断和轮转检查。持久化按原始证据幂等写入，重复读取与重启不会再次累计同一证据。回读受 `LookbackSeconds`、`MaxLines` 和 `MaxFileBytesPerPoll` 限制，应按实际日志量配置。

