# 前端开发规则

本文件补充根 AGENTS.md，适用于 frontend/。管理台基于 Ant Design Pro 6.0.3，业务页面已实现并接入本机管理 API；模板示例页面已移除，保留的模板配置只作为工具链基础。

## 工具链

- 使用 npm 和 package-lock.json，不引入 yarn 或 pnpm 锁文件。
- Biome 是唯一 lint/format 工具。
- 写 antd 组件前先用 npx antd info Component 查询 API。
- `config/routes.simple.ts` 是模板遗留示例路由，`npm run simple` 会用它覆盖 `config/routes.ts` 并删除模板目录，禁止在本业务仓库执行。
- npm 命令只在实际执行后记录结果，不能把模板自带 mock 当作业务实现。

## 结构约定

- 路由在 config/routes.ts。
- 页面放在 src/pages/模块。
- 请求封装放在 src/services/模块。
- 文案放在 src/locales/zh-CN/、src/locales/zh-TW/ 和 src/locales/en-US/。
- Umi 生成的临时目录（.umi*）不手改；接口封装与类型在 src/services/ipban/ 按后端实际合同维护。
- 页面使用 config/defaultSettings.ts 的布局设置和 Ant Design token。

## IPBan 业务约定

- 管理台访问同源 HTTPS API，后端默认监听 0.0.0.0，IPv6 不默认绑定。
- 前端不执行系统命令，防火墙操作通过 Agent API 完成。
- 页面展示 BanDecision、FirewallApplied、FirewallFailed/Disabled 和 ProtectionDegraded 的实际状态。
- 登录事件页面与当前连接、当前登录会话页面分开。
- 当前会话页面支持查看连接详情和人工断开；普通 Ban 默认只阻止新连接。
- Full、IpEnforceable、ObserveOnly 事件的缺失字段显示明确状态，不伪造 Unknown。
- 多用户同权管理，不做 RBAC；最终鉴权由后端完成。
- 不把 Token、Cookie、密钥、名单内容写入 localStorage、URL 或前端日志。
- 批量封禁、解封、会话断开、证书上传和服务重启需要二次确认。
- 一期不提供 macOS 主机支持，也不提供防火墙恢复、规则对账和历史补写页面；MCP 服务页只管理本机接口的启停、工具与密钥，默认关闭。

## 验证

- 前端页面与构建配置变更后运行 npm run lint、npm test；构建相关变更再运行 npm run build。
- 页面需检查主要视口、空态、错误态、数据缺口、事件完整性等级和防火墙降级状态。
- 未安装依赖、未运行构建或未做浏览器验证时如实标注。

