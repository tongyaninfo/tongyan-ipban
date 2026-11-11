# 管理台前端

通研 IPBan 管理台使用 React 19、Umi Max、Ant Design Pro 6.0.3、Biome 和 Vitest。前端构建结果会复制到后端 wwwroot，由同源 HTTPS 服务提供。

- 通研官网：<https://www.tongyaninfo.com>
- 产品官网：<https://ipban.tongyaninfo.com>

## 当前状态

- 管理台页面已实现并接入本机管理 API：页面通过 `src/services/ipban/` 调用同源 `/api`，不依赖 mock 数据，也没有模板示例页。
- 已实现运行总览、登录事件、当前网络连接、当前会话、封禁决定、封禁记录、黑白名单、自动封禁策略，以及系统管理下的 IP 数据库、通知设置、系统设置（含 Syslog 转发状态）、用户、证书、系统日志、操作审计、MCP 服务、备份管理，另有登录页、使用文档页和异常页。
- 前端权限只影响菜单与操作入口的展示，最终鉴权由后端完成。
- 已配置通研 IPBan 标题、品牌图标、本地 `/api` 代理和 `build:backend` 复制脚本；生产构建不依赖开发代理。
- 后端管理台默认监听 HTTPS 0.0.0.0，IPv6 不默认绑定。
- 页面不直接执行系统命令，防火墙操作通过后端 Agent 完成。

## 本地开发

在 `frontend/` 下执行 `npm ci`；如需从仓库根操作，可用 `npm ci --prefix frontend`。安装后由 `prepare` 自动运行 `max setup` 生成 Umi 临时文件。提交信息规范见根目录 [CONTRIBUTING.md](../CONTRIBUTING.md)。

    cd frontend
    npm ci
    npm run dev

开发服务器把 `/api` 代理到本机管理 API `http://localhost:5180`；其他环境地址在 `config/proxy.ts` 中按部署环境填写占位。

## 构建与验证

    cd frontend
    npm run lint    # Biome lint + tsc --noEmit
    npm test        # Vitest 单元测试
    npm run build   # 生产构建，输出到 dist/

需要把构建产物同步到后端 wwwroot 时使用：

    npm run build:backend

构建产物 `dist/`、Umi 临时目录 `.umi*` 和 `node_modules/` 已被 `.gitignore` 排除，不进入仓库。

## 约定

- 路由在 `config/routes.ts`，页面在 `src/pages/`；
- 请求封装在 `src/services/ipban/`；
- 文案在 `src/locales/zh-CN/`、`src/locales/zh-TW/` 和 `src/locales/en-US/`；
- 主题设置沿用 `config/defaultSettings.ts` 和 Ant Design token；
- Token、Cookie、私钥和名单内容不写入 localStorage、URL 或前端日志；
- 前端不做访问控制，权限与状态判定以服务端返回为准。

## 许可

前端基于 Ant Design Pro 6.0.3 模板（MIT）；模板许可原文见 [LICENSE](./LICENSE)。
