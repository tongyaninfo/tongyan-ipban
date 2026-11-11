# 接口合同

本目录维护管理 API 和前端合同的约定。管理 API 与 SignalR 使用当前登录会话鉴权，通过本机 Agent IPC 查询连接、采集事件并执行防火墙操作。服务不提供健康探测接口。

## 通用约定

- 管理 API 使用统一前缀 /api/admin/v1。
- 业务接口返回 ApiResult<T> 和真实 HTTP 状态码。
- 错误不泄露堆栈、连接串、密钥、内部地址或宿主命令。
- 分页使用 page、pageSize、total；排序字段白名单校验。
- 时间存储 UTC，传输使用带时区的 ISO 8601，界面按浏览器时区展示。
- long 型 ID 使用十进制字符串；ID 由 IIdService/YiteIdService 生成。
- 危险写操作需要认证、二次确认和可靠审计。
- 名单、策略、封禁和配置更新携带版本或修订号，冲突返回 409。
- Agent 的防火墙命令只能通过本机 IPC 的类型化请求触发，Api 不接受任意系统命令。

## 状态和错误

| HTTP | 使用场景 |
| --- | --- |
| 200 | 查询或更新成功 |
| 201 | 创建成功 |
| 202 | 已受理但未完成 |
| 400 | 参数或业务校验失败 |
| 401 | 未认证 |
| 403 | 无权限、CSRF 或作用范围失败 |
| 404 | 不存在或不可见 |
| 409 | 版本冲突或状态冲突 |
| 429 | 限速 |
| 500 | 脱敏系统错误 |
| 503 | SQLite、审计、传感器或 provider 不可用 |

规划错误码包括 AUTH_*、LIST_*、GEO_*、POLICY_*、BAN_*、SESSION_*、FIREWALL_*、STORAGE_* 和 SYSTEM_*。

## 规划接口分组

| 分组 | 内容 |
| --- | --- |
| 认证与用户 | 登录、退出、当前用户、账号和密码 |
| 登录事件 | 查询、详情、证据来源、完整性等级和数据缺口 |
| 当前连接 | 当前 TCP 连接、监听端口、端点和进程 |
| 当前会话 | SSH、RDP、VNC、WinRM 会话和人工断开 |
| 名单 | IP/CIDR 查询、创建、更新、停用、导入导出 |
| 策略 | 自动封禁策略、版本、启停和回滚 |
| 封禁 | BanDecision、FirewallAction、解封和误封 |
| 防火墙 | provider、能力和 Enabled/Disabled/Failed 状态 |
| 存储 | 日志留存、轮转、压缩、导出、备份和大小 |
| HTTPS | 自签名证书、证书上传和服务重启 |
| 审计 | 操作审计查询和脱敏导出 |

当前已实现的骨架查询：

| 方法 | 路径 | 当前行为 |
| --- | --- | --- |
| GET | `/api/admin/v1/system/status` | 返回平台和防火墙状态骨架 |
| GET | `/api/admin/v1/connections` | 通过本机 Agent IPC 返回 Linux 当前 TCP 连接；Agent 不可用时返回失败 ApiResult |
| POST | `/api/admin/v1/connections/disconnect` | 按完整连接快照下线单条当前 TCP 连接，不修改防火墙；过期快照和 IPBan 管理连接会被拒绝 |
| POST | `/api/admin/v1/bans` | 按 `sourceAddress`、`durationSeconds`（默认 180）和 `disconnectExisting` 请求人工封禁。`-1` 表示永久，限时接受 1 至 604800 秒。永久封禁必须填写 `reason`，最多 500 字 |
| POST | `/api/admin/v1/bans/unban` | 按 `sourceAddress` 和十进制字符串 `actionId` 解除当前有效封禁，返回实际防火墙结果并记录当前管理员审计；记录已解除或被新封禁替代时返回 409 |
| GET | `/api/admin/v1/firewall-actions` | 返回执行历史，`status` 保留当次执行结果，`currentStatus` 表示当前状态，`canUnban` 控制是否可对该记录手动解封 |
| GET | `/api/admin/v1/login-events?limit=100` | 通过本机 Agent IPC 返回已持久化的登录成功和失败事件 |
| GET | `/api/admin/v1/sessions` | 根据活动连接识别 SSH、RDP、WinRM 和 VNC 会话，从匹配的成功登录事件补齐用户名 |
| POST | `/api/admin/v1/sessions/{sessionId}/disconnect` | 根据当前会话标识定位并断开对应连接 |
| GET | `/api/admin/v1/overview` | 聚合登录事件、活动连接/会话、数据库大小和防火墙观测状态 |
| GET | `/api/admin/v1/users` | 返回本机用户摘要 |
| GET/PUT | `/api/admin/v1/settings`、`/api/admin/v1/settings/{key}` | 查询和更新系统设置 |
| GET/POST | `/api/admin/v1/backups` | 查询和创建 SQLite 备份 |
| GET/POST | `/api/admin/v1/certificates`、`/api/admin/v1/certificates/upload` | 查询证书元数据、上传 PFX 证书 |
| GET | `/api/admin/v1/audit` | 查询可靠操作审计 |
| GET | `/api/admin/v1/logs/files`、`/api/admin/v1/logs`、`/api/admin/v1/logs/export` | 查询结构化 NDJSON 日志文件，支持关键词、严重级别和应用名筛选及导出 |
| DELETE | `/api/admin/v1/logs/files/{fileName}` | 删除一个已轮转的日志归档，记录当前管理员的删除请求和执行结果 |

MCP 作为独立扩展接入，合同见下方「MCP 服务」。

手动解封使用原封禁记录的防火墙执行器。旧的到期任务仅能解除它对应的封禁记录，不能影响后续新建的封禁。解封之前的失败事件不再参与重新封禁，新失败仍按启用策略及冷却期计算。封禁和解封动作写入后，通过已鉴权的 `security-events` 订阅通知页面重新查询。

「实时状态」提供两个独立页面。当前会话订阅 `connections` 和 `security-events`，当前网络连接订阅 `connections`。状态码由前端按当前语言显示，例如简体中文将 `ESTAB` 显示为「已建立」。

日志文件列表的 `canDelete` 表示能否发起手动删除。删除接口仅接受日志目录内符合轮转命名规则的单个归档文件名，包含未压缩和 gzip 归档。管理台在执行前显示文件名并要求确认。

日志查询和导出可传 `severity`（Syslog 数字级别 0–7）和 `appName`（例如 `ipban-ban`），两者均为精确筛选。未筛选时可查看旧格式原始行；无相应结构化字段的旧记录不匹配级别或模块筛选。

### Syslog 转发

| 方法 | 路径 | 合同 |
| --- | --- | --- |
| GET | `/api/admin/v1/syslog/settings` | 读取全局启用状态、`configRevision` 和目标列表 |
| PUT | `/api/admin/v1/syslog/settings` | 使用读到的版本保存；冲突返回 HTTP 409；配置与本地审计同事务提交 |
| POST | `/api/admin/v1/syslog/test` | 提交已保存的 `targetId` 和 `configRevision`，发送合成测试日志 |
| GET | `/api/admin/v1/syslog/status` | 读取期望版本、API/Agent 已应用版本及各目标积压、最近发送/确认、重试与丢弃统计；Agent 不可达时单独标明 |

目标支持 `udp`、`tcp`、`tls`、`relp`，级别上限 `maxSeverity` 默认 7。IPBan 统一使用 `local0` 编码报文，读取旧设置时会忽略其中的 `facility` 字段。`ignoreSslErrors` 仅适用于 TLS，缺省为 false。TCP 的 `framing` 可选 `octet` 或 `lf`；其他协议不接受 LF。目标 ID 和 `deliveryTargetVersion` 由服务端生成；切换端点或传输语义会改变目标版本，历史待发队列不会随之转到新地址。

测试结果只确认协议能力能证明的阶段：UDP 已交给本机网络栈，TCP/TLS 完成本地写入，RELP 收到对端确认；任何协议都不以此证明接收端已落盘。测试与配置保存分离，停用自动转发时仍可显式测试已保存的目标。

完整事件分级、中文日志、`syslog-计算机名`、模块应用名和缓冲规则见 [Syslog 实施方案](../spec/Syslog转发与日志分级实施方案.md)。

运行总览的 `topSourceIps` 按所选时间范围统计，返回事件总数 `count` 最高的 10 个来源 IP。每个来源的 `success`、`failure`、`observeOnly` 互斥且合计为 `count`。完整性等级为 `ObserveOnly` 的事件计入观察，其余事件按登录结果计入成功或失败。同一时间范围内缺少来源 IP 的观察事件通过 `observeOnlyWithoutIp` 单独返回数量。

Windows Security 4624/4625 无法识别应用协议时，登录事件的协议为 `Unidentified`（枚举值 `5`）。读取历史事件时，原先回退为 SSH 且缺少 OpenSSH 进程证据的 Windows Security 事件按同一规则归类。

## MCP 服务

在「系统管理 → MCP 服务」可通过 HTTP 或 HTTPS 启动服务和创建 API Key。服务默认关闭，启动后客户端使用 Streamable HTTP 连接 `/mcp`，每个请求携带 `Authorization: Bearer <API_KEY>`。复制接入指令使用浏览器当前的协议、主机和端口拼接 `/mcp`，反向代理应在同一 origin 转发该路径。接入使用支持自定义请求头及所选协议的 MCP 客户端，业务结果按原生 MCP 格式返回。HTTP 上的请求及凭据以明文传输，跨不受信网络使用 HTTPS。

每把 Key 创建时确定名称、只读或读写、工具权限和到期时间。有效期留空为永久有效。只读 Key 只能选查询工具，读写 Key 还需勾选每个写工具。工具列表和执行分别校验权限，吊销后拒绝新调用。仅允许删除已吊销的 Key，历史调用记录保留。Key 和审计记录的 ID 均以十进制字符串传输。

| 权限组 | 查询工具 | 可单独授权的写工具 |
| --- | --- | --- |
| 运行总览 | `get_overview` | |
| 实时状态 | `list_connections`、`list_sessions` | `disconnect_connection`、`disconnect_session` |
| 安全事件 | `list_login_events`、`list_firewall_actions` | `create_ban`、`create_permanent_ban`、`unban` |
| 访问控制 | `list_access_list`、`list_ban_policies` | `upsert_access_list_entry`、`update_ban_policy`、`set_ban_policy_enabled` |
| 系统诊断 | `list_log_files`、`list_backups`、`list_certificates`，返回元数据 | |

`create_ban` 接收 `sourceAddress`、`reason` 和 `durationSeconds`（1 至 604800 秒）。`create_permanent_ban` 接收 `sourceAddress` 和 `reason`，需要单独授权，返回的 `durationSeconds` 为 `-1`。已有 API Key 可继续调用原已授权的工具。使用永久封禁工具时，创建一把勾选该权限的读写 Key。

管理台和 MCP 的永久封禁都可通过现有解封操作解除。Agent 不安排自动到期，规则能否在防火墙重载或宿主重启后保留取决于现有执行器。例如 firewalld 写入运行时规则。人工下线通过独立工具对单条连接快照执行。编辑或启停自动封禁策略会影响 Agent 后续的自动封禁和连接处置。业务调用失败仍区分已拒绝、执行失败和结果待核验，IPC 超时等无法确认结果的写调用不自动重试。

管理接口使用当前管理员会话和 `ApiResult`。以下路径均以 `/api/admin/v1/mcp` 开头。POST、PUT、DELETE 需要同源请求及 `X-IPBan-Management: 1` 请求头。

| 方法 | 路径 | 行为 |
| --- | --- | --- |
| GET / PUT | `/settings` | 查询和更新 `enabled`、`auditRetentionDays`，缩短时提交 `confirmShorter: true` |
| GET | `/tools` | 返回工具授权目录 |
| GET / POST | `/keys` | 列出 Key 或创建 Key，创建响应一次返回明文 |
| POST | `/keys/{id}/copy`、`/keys/{id}/revoke` | 获取接入指令所需的 Key 明文或吊销 Key，复制操作记管理审计 |
| DELETE | `/keys/{id}` | 删除已吊销 Key |
| GET | `/audits`、`/audits/{id}` | 分页筛选调用记录或查询详情 |

调用审计保留 IP、工具、普通请求头、业务参数、响应、耗时和关联 ID。认证材料只显示提供状态。无效凭据和无法解析或超限的请求仅保存拒绝所需元数据。默认留存 30 天，可设置为 1–3650 天。缩短后由后台分批清理超期的已完成记录。写操作先持久化调用审计，无法确认结果时可按关联 ID 核对。

Agent 使用 SQLite v6 正向迁移，升级前通过 SQLite 备份接口取得包含已提交 WAL 数据的一致副本。旧 Agent 无法读取 v6。API 使用独立的 `Mcp:WorkerId`（默认 `2`），应与 Agent 及其他发号进程的 WorkerId 区分。Key 验证使用摘要，复制使用加密副本。`mcp-key-protection.bin` 只允许 API 服务账号访问，应与数据库分别受控备份，恢复复制功能时需要两者对应。

## 自动策略的封禁时长

`PUT /api/admin/v1/policies/{id?}` 的 `banDurationSeconds` 接受 `-1`（永久封禁）、`0`（不封禁）或 `1` 至 `2147483647` 的整数秒（限时封禁）。保存 `0` 时，服务端将动作记为 `Observe`。旧版本以动作 `Ban` 保存的 `0` 继续按永久封禁执行，查询时返回 `-1`。永久封禁可通过手动解封接口解除。编辑后的时长适用于新触发的封禁。

名称、阈值、窗口、观察期、冷却期和时长由服务端校验。超范围数值、小数及非法 JSON 返回 HTTP 400 和统一 `ApiResult`。时长字段使用 `INVALID_BAN_POLICY_DURATION`，其他数值字段分别使用 `INVALID_BAN_POLICY_THRESHOLD`、`INVALID_BAN_POLICY_WINDOW`、`INVALID_BAN_POLICY_OBSERVE`、`INVALID_BAN_POLICY_COOLDOWN`。客户端按当前语言显示字段提示。

## IP 归属地解析

「系统管理 → IP 数据库配置」独立管理归属地展示。服务默认关闭，预置 `https://ip.tongyaninfo.com/`、端口 `443`、数据库 `CZ88`、超时 `2` 秒。数据库可选择 `CZ88`、`ip2location`、`ip2region`、`dbip`、`ipinfo`、`geolite2`。协议只接受 `http`、`https`，主机字段不包含路径、端口或凭据；端口为 1–65535，超时为 0.1–30 秒。

以下接口使用管理员会话和 `ApiResult<T>`，路径前缀为 `/api/admin/v1/ip-location`。PUT、POST 请求需要 `X-IPBan-Management: 1`，浏览器请求校验同源。

| 方法 | 路径 | 合同 |
| --- | --- | --- |
| GET | `/settings` | 返回 `enabled`、`protocol`、`host`、`port`、`database`、`timeoutSeconds` |
| PUT | `/settings` | 保存整份配置；与管理员审计同一事务提交，成功后切换解析配置 |
| POST | `/lookup` | 接收 `{ "ips": ["192.0.2.1"] }`，每批最多 100 项；立即返回缓存或排队状态，不等待外部查询 |

批量查询 `data` 为 `{ enabled, revision, items }`。每个结果包含 `ip`、`status`，以及允许为空的 `country`、`province`、`city`、`district`、`region`、`isp`、`asn`、`asName`、`database`、`version`、`attribution`、`licenseUrl`。`revision` 标识当前运行配置，前端不得用旧配置的结果覆盖新结果。

| 状态 | 含义 |
| --- | --- |
| `disabled` | 解析开关关闭，不请求外部服务 |
| `private` / `reserved` | 内网、回环或保留地址，由本地识别 |
| `network` | CIDR 网段，不推断整个网段的单点归属地 |
| `invalid` | 无效地址 |
| `queued` | 已排队或正在后台解析 |
| `resolved` | 已得到可展示字段 |
| `notFound` | 数据库未提供可展示的归属字段 |
| `timeout` / `failed` | 本次解析超时或失败，不影响原业务数据 |
| `busy` | 队列繁忙，可稍后再申请 |

后台固定并发 2、队列最多 512 项、缓存最多 10,000 项；成功缓存 24 小时，失败短缓存 1 分钟。配置切换或关闭会使缓存失效并取消旧任务。上游只允许 HTTP/HTTPS，不自动跟随重定向，响应体最多 128 KiB；超时覆盖响应体读取。缓存仅驻留内存，服务重启后按页面需求重新解析。`IpBan.IpLocation` Meter 暴露队列、缓存、在途数量和完成、失败、入队拒绝计数。

系统通用设置接口不能直接修改保留配置键 `ip-location`。本功能不增加 SQLite 表、列或迁移。解析仅用于展示，外部服务异常不参与封禁判定；开启后会将展示中的公网 IP 发送至配置的服务。数据库可能不提供国家、省、市或区，客户端只显示现有字段。

## 邮件通知

「系统管理 → 通知设置」管理 SMTP 服务、通知规则和发送记录。登录通知仅来自主机 SSH、VNC、RDP、OpenSSH、WinRM 等采集事件，不包含管理台账号登录。总开关默认关闭，四类规则默认开启；只处理启用后的新事件，不补发历史记录。

以下接口使用管理员会话、统一 `ApiResult<T>` 和 `Cache-Control: no-store`，前缀为 `/api/admin/v1/notifications`。PUT、POST 需要 `X-IPBan-Management: 1`，浏览器请求需同源；请求体上限为 32 KiB。

| 方法 | 路径 | 合同 |
| --- | --- | --- |
| GET | `/settings` | 返回整份配置、`hasCredential`、`revision`、`enabledSinceUtc`；不返回授权码或密文 |
| PUT | `/settings` | 接收 `{ settings, credential?, clearCredential? }`；配置与可靠审计同事务保存，返回新修订号 |
| POST | `/test` | 接收 `{ "recipient": "admin@example.com" }`；返回 `{ messageIds }`，其中 ID 是排队记录的十进制字符串编号，成功仅表示已入队 |
| GET | `/messages?page=1&pageSize=20&status=sent` | 按状态、`eventType` 分页查询；不指定状态时返回所有状态 |
| GET | `/messages/{id}` | 返回记录摘要、已保存 HTML/纯文本、模板版本、SMTP Message-Id 和事件样本 |
| GET | `/preview/{eventType}` | 返回合成数据的模板预览，不发送邮件；接受四类事件及 `test`、`summary` |

配置以 [NotificationSettings](../../backend/src/IpBan.Shared/Models/NotificationContracts.cs) 为准：

| 字段 | 默认值及限制 |
| --- | --- |
| `enabled` | `false`；开启需完整 SMTP、发件邮箱、收件人和已保存授权码 |
| `host`、`port` | 主机名或 IP，不能带协议、路径或账号；端口默认 465，范围 1–65535 |
| `security` | 默认 `ssl`（连接即 TLS）；可选 `starttls`（必须升级 TLS）、`none`（不加密） |
| `fromAddress`、`username`、`fromName` | 发件邮箱、SMTP 登录账号、显示名称；账号留空时使用发件邮箱，名称默认「通研技术」 |
| `recipients` | 最多 10 个有效邮箱，忽略大小写去重；每个收件人独立任务 |
| `maxPerMinute`、`maxPerHour` | 默认 10、60；每分钟 1–120，每小时不得小于每分钟且最多 10000 |
| `retryCount` | 默认 3，范围 0–5，指首次尝试之外的最大重试次数 |
| `queueLifetimeHours` | 默认 24，范围 1–168 小时 |
| `retentionDays` | 默认 30，范围 1–365 天 |
| `rules` | 必须恰好包含 `loginSuccess`、`loginFailure`、`ban`、`unban`；各项有 `enabled`、`intervalSeconds` |
| `revision` | 读取后原样提交，过期修订号返回 409；不能省略并覆盖已有配置 |
| `hasCredential`、`enabledSinceUtc` | 服务端维护；分别表示是否保存授权码、当前启用周期的起始时间 |

授权码通过外层 `credential` 写入，不属于普通配置 JSON；省略或空字符串保留原值，`clearCredential: true` 明确清除，不能同时提交新授权码。启用状态下不能清除唯一凭据。页面提供带二次确认的清除按钮，只在总开关已经关闭且没有未保存修改时可用。通用系统设置接口拒绝直接写入 `notifications.*`。

默认规则间隔为登录成功 300 秒、登录失败 600 秒、封禁/解封各 60 秒，可配置 10–86400 秒。登录成功按来源 IP、协议、用户名分组，失败按 IP、协议分组，封禁/解封按 IP 分组；各事件类型互不合并。首批可立即排队，后续按间隔汇总。`eventCount` 为本封新增事件数，详情 `events` 最多保存 100 条样本，邮件最多列出 20 条。如果同组上一封单条登录通知已由该收件人的 SMTP 接收，且本封新增事件都在首条发生后的规则间隔内，正文会同时显示含首条的累计次数和本封新增次数。

登录成功、登录失败及其汇总邮件的标题追加 `源IP->用户名@本机IP`。本机 IP 优先使用事件的本地端点地址，缺失时取 Agent 所在主机运行正常的物理网卡上的可用单播地址。缺失字段显示「未提供」。汇总标题取本封首条新增事件的快照。已排队和历史邮件沿用生成时保存的标题。

全局额度按固定窗口内的 SMTP 尝试计数，包括重试和测试；每个收件人分别占用一次额度。计数在 SQLite 持久化，重启不清零。登录通知最多占额度的 80%（向下取整，最低 1 次），封禁、解封及测试仍受全局上限。测试邮件额外限制每分钟一次，使用已经保存的配置，总开关关闭时仍可显式测试。

候选上限为 10000 条，达到 8000 条后不再接收登录候选，为封禁/解封保留余量；溢出计入 `suppressedEvents`，原业务记录继续保存且不被淘汰。待发任务上限为 1000，登录通知最多占 800 个槽位。Agent 仅接收发生时间晚于 `enabledSinceUtc` 且来源年龄不超过 `min(queueLifetimeHours, 24)` 小时的新候选；已经入队的任务再按队列有效期过期。配置更新取消旧的待处理候选及 `queued`、`retry` 任务，保留已发送快照。

消息列表 `data` 包含 `items / total / page / pageSize / pendingEvents / suppressedEvents`。`page` 为 1–100000，`pageSize` 为 1–100；`eventType` 可筛选四类事件或 `test`。摘要包含字符串 `id`、类型、状态、收件人、主题、来源 IP、事件数量、尝试次数、创建/发送/下次尝试时间，以及脱敏错误码和说明。详情还包含 `htmlBody / textBody / templateVersion / messageId / events`，历史内容不会随模板更新而重新渲染。

| 投递状态 | 含义 |
| --- | --- |
| `queued` | 已排队，等待额度与后台处理 |
| `sending` | 已领取任务并开始一次尝试，持有有限租约 |
| `retry` | 暂时性失败，等待退避时间；默认重试间隔为 1、5、15 分钟，后续沿用 15 分钟 |
| `sent` | SMTP 已接受邮件，不等同收件箱送达 |
| `failed` | 永久性错误或重试次数耗尽；`SMTP_DELIVERY_UNCERTAIN` 表示上次投递结果无法确认且不能继续重试，需核实收件结果 |
| `expired` | 超过队列有效期，停止投递 |
| `cancelled` | 配置更新或关闭时取消的旧任务 |

邮件主题固定以 `通研IPBan-` 开头，HTML 模板位于后端 `Resources/EmailTemplates` 并作为嵌入资源发布。`Applied`、`Removed` 分别表示实际封禁、解封成功；`Failed`、`Disabled` 不展示为已生效。实际解封前不能因预计到期而发送成功通知。

典型错误为 400 `INVALID_NOTIFICATION_SETTINGS` / `INVALID_NOTIFICATION_CREDENTIAL` / `INVALID_NOTIFICATION_FILTER`、403 `NOTIFICATION_ORIGIN_REQUIRED`、404 `NOTIFICATION_NOT_FOUND`、409 `NOTIFICATION_SETTINGS_CHANGED`、413 `NOTIFICATION_BODY_TOO_LARGE`、429 `NOTIFICATION_TEST_RATE_LIMITED` / `NOTIFICATION_QUEUE_FULL`、503 `NOTIFICATION_STORAGE_UNAVAILABLE`。429 响应携带 `Retry-After: 60`，队列满时该值不保证一分钟后已有空间。

同组仍有待发任务时继续累计候选，不产生多封积压摘要；领取新的邮件时还检查该收件人上次实际发送时间，服务恢复后仍保持来源间隔。租约恢复也受首次尝试加重试次数的总预算约束。已发送邮件的保留天数从 SMTP 接收时间计算，其余已结束任务按创建时间计算。

本功能使用经授权新增的 SQLite v7 三表。升级时先让 Agent 完成 v7 迁移，再启动新版 API。密钥文件 `notifications-key-protection.bin` 必须与数据库分别备份；密钥丢失时不能自动替换旧密文的解密密钥。SMTP 由 MailKit 执行，保留默认主机名和证书链校验，单次连接与发送期限为 15 秒，认证或 TLS 永久错误不自动重试。稳定 Message-Id 用于关联重试，不能提供 exactly-once 保证。架构与实际验证边界见 [ADR-0002](../adr/ADR-0002-邮件通知与持久化发送.md)。

## 合同链

后端 DTO 和路由是合同来源：

    后端 DTO/路由
      → 合同导出
      → 前端类型与服务封装
      → 合同漂移检查

合同链建立前，不手改生成文件，不把模板 mock 当作业务合同。

