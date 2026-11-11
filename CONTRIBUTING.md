# 参与贡献

感谢参与通研 IPBan。本文说明开发环境、本地验证、代码约定、提交要求与脱敏边界。

## 开发环境

- **.NET SDK** 10.0.x（根 `global.json` 固定为 10.0.300，可用 `rollForward` 使用更新的补丁版本）
- **Node.js** 22 或更高版本（`frontend/package.json` 要求 `>=22.0.0`），使用 npm 与 `frontend/package-lock.json`
- **SQLite** 由应用内嵌，无需单独安装
- **Windows/Linux 主机**：验证登录采集、连接关联与防火墙处置时需要；只使用用户明确批准的隔离主机

## 本地验证

提交前请在仓库根目录运行与改动范围对应的检查：

```sh
# 文档：Markdown 本地相对链接
node scripts/check-docs.mjs

# 后端：构建与测试
dotnet build backend/IpBan.slnx
dotnet test backend/IpBan.slnx --no-build

# 前端：类型与 lint、单元测试、构建
cd frontend
npm ci
npm run lint
npm test
npm run build
```

没有实际运行的检查不要写成通过；被环境阻塞时注明原因与未验证范围。封禁链路的验证只能使用隔离数据与合成来源，不在真实网络或生产主机上试验封禁效果。

## 代码约定

- 后端：Controller 只处理 HTTP 参数、状态码与服务调用；判定编排、名单匹配、策略求值与审计写入放在对应服务。接口统一返回 `ApiResult<T>` 并保留真实 HTTP 状态码。
- 后端：时间存 UTC、对外传带时区 ISO 8601，界面默认按 Asia/Shanghai 展示；长整型 ID 在 JSON 中以十进制字符串传输。
- 后端：Agent 以高权限运行，负责采集、SQLite、防火墙与当前会话；Api 与 Agent 通过本机 Unix Domain Socket 或 Windows Named Pipe 通信，不开放 Agent 命令为网络接口。
- 后端：防火墙关闭或执行失败时只记录 Disabled/Failed，不提供自动恢复、规则对账或历史补写；文档必须区分 BanDecision、FirewallApplied 与 FirewallFailed/Disabled。
- 前端：路由在 `frontend/config/routes.ts`、页面在 `frontend/src/pages/`、请求封装在 `frontend/src/services/ipban/`、国际化在 `frontend/src/locales/`。前端不承担访问控制，权限以服务端校验为准。
- 前端：Biome 是唯一 lint/format 工具，不混用其他格式化配置；页面改动需要在真实浏览器验证主要视口、错误态与空态。
- 新增依赖、升级版本、修改公共组件、数据库结构或防火墙 provider 前先说明范围与影响，不在无关改动中顺手重构。

## 提交信息

格式：

```
type(scope): 描述
```

- `type` 限 `feat`、`fix`、`docs`、`style`、`refactor`、`perf`、`test`、`chore`、`ci`、`revert`、`merge`。
- `type` 后紧跟括号与冒号，冒号后一个空格；描述使用中文，1～50 字。
- `scope` 建议使用模块名，例如 `agent`、`api`、`engine`、`ui`、`docs`、`deploy`。

示例：`fix(agent): 修正日志轮转后 SSH 事件重复采集`。

## 提交前检查

1. 只涉及本次改动，不夹带无关格式化或依赖升级。
2. 不提交 `bin/`、`obj/`、`node_modules/`、`dist/`、`frontend/src/.umi*`、`backend/src/IpBan.Api/wwwroot/`、运行数据、数据库、证书与备份。
3. 不提交真实主机、内网地址、账号、口令、SMTP 授权码、Token、私钥、真实登录事件或可定位个人的截图。
4. 测试与截图使用合成数据，来源地址使用文档保留网段（`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`、`2001:db8::/32`）或私有网段示例。
5. 文档改动同步更新相关链接与状态标注，不留失效链接；公开文档不描述内部部署记录、内部主机与内部流程。

## 拉取请求

- 从 `main` 创建分支，保持单一主题；说明改动范围、验证命令与结果、未验证边界。
- 涉及行为变化时补充或更新测试；涉及接口变化时同步更新 `docs/api/` 与前端请求封装。
- 涉及安全敏感区域（认证、会话、证书、SMTP 凭据、MCP 权限、防火墙执行、日志清空）时说明威胁边界与测试方式。
- 评审意见处理完成后再请求合并；合并由维护者执行。

## 安全问题

不要通过公开 Issue 或 Pull Request 披露漏洞细节，请按 [SECURITY.md](SECURITY.md) 的流程报告。
