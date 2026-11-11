# Docker 部署

本目录当前没有 Dockerfile、Compose 文件或构建脚本。Docker 只作为后续单机部署形态，实际 Agent 的 root/Administrator 能力、Linux 传感器和防火墙权限需要在获准隔离环境验证。

## 规划

- 前端用 Node.js 构建，产物复制到后端 wwwroot，运行镜像不含 Node.js。
- 后端发布包含 IpBan.Api、IpBan.Agent、IpBan.Engine 和 IpBan.Shared。
- SQLite、日志、备份和配置使用宿主卷。
- Api 和 Agent 通过容器内本机 IPC 通信，不能把 Agent 原始命令暴露为网络接口。
- 管理台默认使用 HTTPS 0.0.0.0，IPv6 不默认绑定。
- 防火墙 provider 支持 Windows/Linux 目标环境；容器是否能访问宿主防火墙需要目标环境单独授权和验证。
- 不提供防火墙自动恢复、规则对账、历史补写和恢复动作审计。

## 初始化顺序

1. 建立后端和前端工程。
2. 验证 dotnet build、dotnet test、前端 lint/test/build 和 AOT 发布。
3. 确认镜像用户、数据卷、日志轮转、端口和健康检查。
4. 首次启动自动创建 SQLite 并执行正向迁移。
5. 在获准隔离环境验证登录采集、传感器、provider、备份和会话页面。

当前无镜像、无 Compose、无宿主环境验收结果。

