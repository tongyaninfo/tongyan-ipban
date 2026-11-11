# 变更日志

本文件按版本记录面向使用者的变化，版本遵循语义化版本；源码版本以根 [VERSION](VERSION) 为准。开发过程中的实现依据与验证边界以各实施方案、ADR 和 [项目开发约定](AGENTS.md) 为准。

## [Unreleased]

暂无。

## [0.1.0] - 2026-11-11（公开首版，未封版）

### 公开说明

本项目首次以 Apache License 2.0 开源，源码范围包括 .NET 10 后端（Agent、Api、判定引擎、公共合同）、React 管理台与方案文档。公开前完成一轮发布检查：测试夹具中的内网地址替换为文档保留网段；移除上游模板残留、构建产物与内部部署记录；敏感信息扫描无阻断项。

### 新增

- 后端：`IpBan.Agent`、`IpBan.Api`、`IpBan.Engine`、`IpBan.Shared` 四个 .NET 10 项目与 `IpBan.slnx`；SQLite 自动初始化与正向、非破坏性迁移；Linux SSH/TigerVNC 与 Windows EventLog 登录采集；当前 TCP 连接与登录会话关联；Unix Domain Socket 或 Windows Named Pipe IPC；firewalld、ufw、nftables、iptables 与 Windows Defender Firewall 执行器；HTTPS 管理 API、账号会话与操作审计。
- 管理台：运行总览、登录事件、当前连接、当前会话、黑白名单、自动封禁策略、封禁决定与封禁记录、IP 归属地、通知设置与邮件记录、Syslog 转发设置、用户、证书、系统日志、操作审计、备份管理和 MCP 管理页。前端基于 React 19、Umi Max 与 Ant Design Pro 6.0.3 模板。
- 通知与转发：SMTP 邮件通知规则、模板与发送记录；UDP、TCP、TLS、RELP Syslog 转发。
- MCP：可选扩展，默认停止，需管理员显式启用并创建受限 API Key，按工具授权、可吊销、调用进入审计。
- 文档：产品 README、一期实施方案、产品规划、功能需求清单、接口合同、ADR、版本与发布说明，以及使用合成演示数据的管理台截图。
- 部署与脚本：部署约束说明、Docker 部署规划说明、Markdown 本地链接检查与开源敏感信息扫描脚本。
- 发布：GitHub Actions 发布工作流（`v*` tag 触发，校验 `VERSION`，构建 win-x64、win-arm64、linux-x64、linux-arm64 自包含包，生成草稿 Release 与 SHA256 校验和）。

### 验证（2026-11-11）

- `dotnet build backend/IpBan.slnx`：0 错误；5 条既有 NU1903 依赖告警，沿用当前依赖版本，未在本次升级。
- `dotnet test backend/IpBan.slnx --no-build`：359 项通过，0 失败，0 跳过。
- 前端 `npm ci`、`npm run lint`、`npm test`、`npm run build`：依赖安装与 `max setup` 成功；Biome 检查 138 个文件、TypeScript 检查通过；19 个测试文件 177 项通过；构建生成 27 个页面入口。
- `node scripts/check-docs.mjs`：92 条本地相对链接通过。
- `node scripts/scan-open-source-sensitive.mjs --root .`：0 阻断项；复核项逐条判定（测试夹具、i18n key、上游模板版权注释等属误报）。

### 未验证

- 真实 Windows/Linux 主机全场景验收，Windows RDP/WinRM 真实登录，Windows Service/systemd 正式部署，Native AOT 跨平台发布。
- 管理台浏览器视口、交互与控制台回归；`build:backend` 产物复制到 `wwwroot` 后的同源静态资源访问。

## [0.1.0-dev] - 2026-11-07

### 新增

- 仓库初始化：目录结构、根开发约定（`AGENTS.md`）、产品 README、版本与工程基础文件。
- 后端目录与规划：`IpBan.Api`、`IpBan.Engine`、`IpBan.Shared` 及对应测试项目说明，尚未初始化 .NET 工程。
- 前端目录与规划：`frontend/` 说明与子规则，尚未拉取 Ant Design Pro 6.0.3 模板。
- 部署与脚本目录说明：`deploy/`、`deploy/docker/`、`scripts/`，含只读的 Markdown 本地链接检查脚本。
- 文档基线：文档中心、项目目录规划、产品规划、功能需求清单、一期实施方案草案、接口约定、变更与版本规约、ADR 与文档资源要求。

### 未完成

- 后端工程、封禁判定引擎与管理接口尚未实现。
- 前端模板与业务页面尚未初始化。
- 数据库、容器部署、名单与 GeoIP 数据源尚未建立。
- 防火墙执行器不在 0.1.0-dev 范围，未设计、未实现。
