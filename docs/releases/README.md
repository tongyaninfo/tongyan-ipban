# 版本与发布

本目录记录版本规则、发布清单、数据库升级和制品约定。当前源码版本为 0.1.1；Release 由 GitHub Actions 在推送 `v*` tag 时构建并直接发布。

## 版本规则

- 根 VERSION 是产品版本唯一来源，当前为 0.1.1。
- CHANGELOG 面向使用者；开发依据、验证边界和范围调整在内部开发记录中维护，不随公开仓库发布。
- 后端、前端和安装包版本从根版本投影，不各自维护另一套版本。
- 数据库迁移编号独立记录，不能重写历史迁移。

## 自动化发布

- 推送形如 `v0.1.1` 的 tag 触发 [Release 工作流](../../.github/workflows/release.yml)；工作流先校验 tag 与根 `VERSION` 一致，不一致直接失败。
- 前端在 Ubuntu runner 上执行 `npm ci` 与 `npm run build`，产物合并到 `backend/src/IpBan.Api/wwwroot`。
- 后端为 win-x64、win-arm64、linux-x64、linux-arm64 四种 RID 分别发布自包含包：`api/`（管理 API、HTTPS 管理台与前端静态文件）与 `agent/`（采集、SQLite 与防火墙 Agent），包内附 `运行说明.txt`。
- 附件包含各 RID 的压缩包与 `SHA256SUMS.txt`；Release 直接发布为正式版本。
- 制品形态为自包含托管发布（`PublishAot=false`）。csproj 默认开启 Native AOT，但 MCP 管理面的 Delegate 路由在 AOT 分析下触发 IL2026/IL3050，AOT 制品待问题修复并验证后再提供。

## 数据库启动和升级

- 服务启动自动创建 SQLite，并执行连续的正向、非破坏性迁移。
- 使用单实例迁移锁、事务和迁移历史。
- 迁移前生成备份；未知、更高或不连续的数据库版本停止并报告。
- 需要删除数据、清空表或不可逆重建时，不由普通启动自动执行。
- 迁移失败保留原数据库和备份，不覆盖或删除。

## 发布矩阵

| RID | 制品 | 形态 |
| --- | --- | --- |
| win-x64 | `IpBan-<版本>-win-x64.zip` | 自包含托管，`api/` + `agent/` |
| win-arm64 | `IpBan-<版本>-win-arm64.zip` | 自包含托管，`api/` + `agent/` |
| linux-x64 | `IpBan-<版本>-linux-x64.tar.gz` | 自包含托管，`api/` + `agent/` |
| linux-arm64 | `IpBan-<版本>-linux-arm64.tar.gz` | 自包含托管，`api/` + `agent/` |

- 未提供 linux-musl 与 Native AOT 制品；需要时先补齐构建与运行验证，再扩展矩阵。
- Windows Service 与 systemd 单元未随制品提供，启动顺序与配置以包内运行说明和 [部署约定](../../deploy/README.md) 为准。
- 发布前必须验证 Yitter、SQLite、WFP 和 eBPF helper 在目标形态下的兼容性；Native AOT 属于待验证项。

## 发布前检查

- 版本、CHANGELOG 和发布记录一致；
- 文档链接和状态标注检查通过；
- dotnet build、dotnet test、npm lint/test/build 实际运行；
- 制品在目标主机按 RID 启动，AOT 制品按 RID 启动（当前制品为托管自包含，AOT 待验证）；
- SQLite 自动迁移、备份和日志留存实际验证；
- 登录采集、当前连接、当前会话、防火墙 provider 和 HTTPS 实际验证；
- 防火墙关闭时没有自动恢复、规则对账或历史补写；
- 制品无真实凭据、私钥、主机信息或客户数据；
- 部署和防火墙验收只在获准隔离环境执行。

## 当前状态

`v0.1.0` 与 `v0.1.1` 已发布，各包含四种 RID 的自包含发布包与校验和。`v0.1.1` 修复 Windows SYSTEM 登录触发邮件通知的问题。制品已在两台测试主机完成部署验证，真实主机全场景验收边界见 CHANGELOG 与各实施方案。
