## 改动说明

<!-- 说明改动的目的、范围和影响。 -->

## 涉及范围

- [ ] 后端 Agent（`backend/src/IpBan.Agent/`）
- [ ] 后端 Api（`backend/src/IpBan.Api/`）
- [ ] 判定引擎与公共合同（`backend/src/IpBan.Engine/`、`backend/src/IpBan.Shared/`）
- [ ] 前端管理台（`frontend/`）
- [ ] 部署与配置（`deploy/`、`appsettings*.json`）
- [ ] 文档（`docs/`、`README.md`、`CHANGELOG.md`）
- [ ] 脚本与 CI（`scripts/`、`.github/`）

## 验证

<!-- 列出实际运行的命令与结果；未运行的检查请注明原因。 -->

```sh
# 示例
dotnet build backend/IpBan.slnx
dotnet test backend/IpBan.slnx --no-build
node scripts/check-docs.mjs
node scripts/scan-open-source-sensitive.mjs --root .
```

## 安全与脱敏

- [ ] 未包含真实主机、内网地址、账号、口令、SMTP 授权码、Token、私钥或真实登录记录
- [ ] 截图与示例数据为合成内容，来源地址使用文档保留网段
- [ ] 涉及认证、会话、证书、SMTP 凭据、MCP 权限、防火墙执行或日志清空的改动已说明威胁边界
- [ ] 未在真实网络或生产主机上试验封禁效果
