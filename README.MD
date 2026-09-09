# CDT Monitor

CDT Monitor 是一个用于阿里云 CDT 流量监控、ECS 实例自动化控制和费用观察的轻量级单机控制台。HTTP 服务、定时调度器、并发 Worker、SQLite、API 和前端静态资源全部集成在一个 Go 进程中，适合通过 Docker 或独立二进制快速部署。

> 目标平台：Linux / Windows / macOS，amd64 / arm64
> 数据库：SQLite WAL，不需要 MySQL 或 Redis

## 功能

- 多阿里云账号、地域和 ECS 实例集中管理。
- CDT 国内/海外流量分类聚合与用量历史图表。
- 可配置流量阈值，支持“停机并通知”和“仅通知”。
- 普通停机 `KeepCharging` 和节省停机 `StopCharging`。
- 每日定时开关机，任务延迟或进程重启后提供短窗口补偿。
- 抢占式实例保活，阈值熔断优先于保活。
- Web 控制台手动开机、关机和刷新。
- SMTP、Telegram Bot、自定义 Webhook 通知；Telegram 支持自定义反代和 SOCKS5。
- 中国站和国际站 BSS 端点、CNY/USD 账单与余额缓存。
- 首次安装向导、管理员 Session、登录限速、CSRF 防护。
- AES-GCM 加密 AccessKey Secret 与通知凭据，管理员密码使用 Argon2id。
- 带 scope、可撤销的 API Key，供 Android、iOS 和桌面小组件使用。
- 自动清理日志/统计，健康检查和 JSON 容器日志。
- 原 PHP SQLite 数据库可原地升级；启动前请先备份 `data/data.sqlite`。

## 架构

```text
浏览器 / 小组件
       │
       ▼
Go HTTP API ──► SQLite WAL 状态快照
       │
       ├──► 内置调度器 ──► 持久化 Job ──► Worker Pool ──► 阿里云 RPC
       │                                      │
       └──► 管理操作                           └──► Notification Outbox
                                                        │
                                             SMTP / Telegram / Webhook
```

状态查询只读取 SQLite 快照，不在页面请求内等待阿里云 API。刷新和控制返回 `202 + job_id`，由后台 Worker 执行。调度租约和动作事件键用于防止任务重叠、重复开关机和重复阈值通知。

更完整的现状与技术决策见 [架构分析](docs/architecture-analysis.md)。

## Docker 安装

上游已发布镜像仍可按下面的 Compose / CLI 示例拉取。本 fork（`86669666/CDT-Monitor`）仓库内的 `docker-compose.yml` 改为本地构建 `cdt-monitor:local`（没有 GHCR/Hub 前缀，避免 `docker compose push` 有仓库可推）。本地步骤见 [本地 Docker](docs/local-docker.md)。

### Docker Compose

```yaml
services:
  cdt-monitor:
    image: ghcr.io/wang4386/cdt-monitor:latest
    container_name: cdt-monitor
    restart: unless-stopped
    init: true
    ports:
      - "43210:8080"
    environment:
      CDT_DATA_DIR: /data
      CDT_LISTEN: :8080
      CDT_WORKERS: 4
      TZ: Asia/Shanghai
    volumes:
      - cdt-data:/data

volumes:
  cdt-data:
```

启动：

```bash
docker compose up -d
docker compose logs -f cdt-monitor
```

浏览器访问 `http://服务器地址:43210`，首次访问会进入安全安装向导。

### Docker CLI

```bash
docker run -d \
  --name cdt-monitor \
  --restart unless-stopped \
  -p 43210:8080 \
  -v cdt-data:/data \
  ghcr.io/wang4386/cdt-monitor:latest
```

Docker Hub 用户也可以使用：

```text
qninq/cdt-monitor:latest
```

运行镜像使用非 root 用户和 `scratch` 基础层，不包含 Nginx、PHP-FPM、Cron、shell 或包管理器。HTTPS 请求所需的 CA 证书会单独复制进镜像。

## 二进制安装

从 GitHub Releases 下载对应平台压缩包，解压后运行：

```bash
./cdt-monitor serve --data ./data --listen :8080
```

Windows：

```powershell
.\cdt-monitor.exe serve --data .\data --listen :8080
```

支持的命令：

| 命令 | 用途 |
| --- | --- |
| `serve` | 启动 Web、调度器和 Worker，默认命令 |
| `run-once` | 创建一轮监控任务并等待执行结束 |
| `migrate` | 执行数据库迁移并退出 |
| `version` | 输出版本、Commit 和平台 |
| `healthcheck` | 请求本机 `/healthz`，供容器健康检查使用 |

环境变量：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `CDT_DATA_DIR` | `./data` | SQLite 和 `master.key` 所在目录 |
| `CDT_LISTEN` | `:8080` | HTTP 监听地址 |
| `CDT_WORKERS` | `4` | 后台任务并发数 |
| `TZ` | 系统时区 | 容器环境时区；业务时区以控制台设置为准 |

## 从 PHP 版本升级

1. 停止旧容器或 PHP Cron，避免两个版本同时执行自动化任务。
2. 完整备份旧 `data/`，尤其是 `data/data.sqlite`。
3. 将同一数据目录挂载到新版 `/data`。
4. 启动新版。程序会补齐 schema，并自动把旧明文 AccessKey Secret、SMTP 密码、Telegram Token 和 Webhook Headers 加密。
5. 使用原管理员密码登录；首次成功登录会把旧明文管理员密码升级为 Argon2id。
6. 检查实例、历史流量、账单、定时计划和通知配置。
7. 创建具有 `cron:run` scope 的专用 API Key，再替换旧的 URL Cron。

新版不会重排账号或日志自增 ID。账号主键保持稳定，历史统计不会因为保存配置而重新绑定。

> `data/master.key` 是解密凭据的必要文件，必须与 SQLite 一起备份。丢失该文件后无法恢复已加密 Secret。

## API Key 与小组件 API

在“设置 → API Key”中创建 Key。Token 只显示一次，数据库只保存 SHA-256 哈希。

权限：

| Scope | 能力 |
| --- | --- |
| `widget:read` | 读取小组件摘要、状态与历史 |
| `instance:control` | 手动刷新、开机和关机 |
| `cron:run` | 调用兼容 URL Cron |

请求示例：

```bash
curl -H "Authorization: Bearer cdt_xxx" \
  http://127.0.0.1:8080/api/v1/widget/summary
```

```bash
curl -X POST \
  -H "Authorization: Bearer cdt_xxx" \
  http://127.0.0.1:8080/api/v1/accounts/1/actions/start
```

主要接口：

```text
GET  /api/v1/widget/summary
GET  /api/v1/status
GET  /api/v1/accounts/{id}/history
POST /api/v1/accounts/{id}/refresh
POST /api/v1/accounts/{id}/actions/start
POST /api/v1/accounts/{id}/actions/stop
GET  /api/v1/jobs/{job_id}
GET  /healthz
GET  /readyz
```

兼容 URL Cron：

```text
GET /monitor.php?key=<具有 cron:run scope 的 API Key>
```

不再支持把管理员密码放在 URL 中。

### Android 桌面小组件

仓库中的 [`android-widget`](android-widget/README.md) 是基于 `/api/v1/widget/summary` 的 Android 小组件原型，源码暂时随主项目保存，供后续研究和完善。当前不作为正式稳定客户端发布。本机 ops 工作区缺少 JDK 17 / Android SDK / Gradle，本地出包记为 blocker；构建走手动 Actions workflow。

## 相关链接

- 项目主页：[GitHub](https://github.com/wang4386/CDT-Monitor)
- 作者博客：[qninq.cn](https://qninq.cn)
- 技术社区：[NodeSeek](https://www.nodeseek.com/) · [Linux.do](https://linux.do/)

## 本地开发

容器方式见 [本地 Docker](docs/local-docker.md)。不要使用 `docker compose push`。

要求 Go 1.24 和 Node.js 22：

```bash
cd web
npm ci
npm run build
cd ..
go test ./...
go run ./cmd/cdt-monitor serve --data ./tmp-data
```

开发前端时可以使用 `npm run dev`，API 请求需要由 Vite 代理或使用同源构建产物测试。

生产构建：

```bash
cd web && npm ci && npm run build && cd ..
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o cdt-monitor ./cmd/cdt-monitor
```

## GitHub Actions

| Workflow | 触发条件 | 输出 |
| --- | --- | --- |
| `CI` | `dev`/`main`/`work/**` push、PR、手动 | 前端构建、Go race test、vet、Linux build（不发布镜像） |
| `Publish Guard` | `dev`/`main`/`work/**` push、PR、手动 | 检查发布变量未打开；扫描 workflow YAML / Compose 是否回到 GHCR/Hub login、`packages: write`、带仓库前缀的镜像名，或把端口改成非 `127.0.0.1`（不发布） |
| `Automatic Release` | 仅手动，且需 `ENABLE_PRODUCTION_PUBLISH` | 按输入版本打 tag，再调用 Release Binaries / Container Images |
| `Release Binaries` | 手动或 Automatic Release `workflow_call`，且需 `ENABLE_PRODUCTION_PUBLISH` | 本 fork 只编 linux/amd64；SHA-256 校验和及 **draft** GitHub Release（不标 latest） |
| `Container Images` | 仅手动或 Automatic Release `workflow_call`（无 `dev`/tag `on.push`） | runner 上 load 校验 linux/amd64 本地标签 `cdt-monitor:verify-amd64`；无 registry login / 镜像名 / push |
| `Android Widget` | 仅手动；本 fork 默认分支尚未登记，dispatch 现为 404 | 原型 APK/AAB artifact（不是本机 JDK 出包，也不是 Play/GHCR）。不要为了登记它去合未加开关的 `main` |

本 fork 默认不发布。`Automatic Release`、GitHub Release 和 GHCR push 需要仓库变量 `ENABLE_PRODUCTION_PUBLISH=true`。Container Images 不再 login，也不再给 GHCR / Docker Hub 打 metadata 名。审计记录见 [CI 发布与密钥审计](docs/ci-publish-audit.md)。不要在本 fork 打开发布变量。

上游已发布镜像标签（不是本 fork 的本地标签）：

- `dev` 分支：`ghcr.io/wang4386/cdt-monitor:dev`、`qninq/cdt-monitor:dev`
- `main` 分支：`ghcr.io/wang4386/cdt-monitor:latest`、`qninq/cdt-monitor:latest`
- Release：两个仓库均发布 `v2.x.x`、`2.x.x` 与 `2.x` 标签

## 安全建议

- 公网部署必须在反向代理或网关层启用 HTTPS。由代理写入 `X-Forwarded-Proto: https` 并覆盖客户端伪造的同名头；HSTS 加在代理层。应用在本地 HTTP Compose 下不会发 HSTS。
- 本 fork 的 Compose 只绑定 `127.0.0.1:43210`。在 `CDT_TRUSTED_PROXIES` 落地前，不要把监听改到局域网或 `0.0.0.0` 并信任私网来源的转发头。说明见 [本地 Docker](docs/local-docker.md)。
- 阿里云 RAM 用户只授予 CDT 查询、ECS 查询/启停和可选 BSS 查询所需的最小权限。
- 小组件只使用 `widget:read` Key；不要把 `instance:control` Key 放入公开脚本。
- 定期撤销不再使用的 Key，并备份整个数据目录。
- 不要把 `data/`、日志或 API Token 提交到 Git。

## License

[MIT](LICENSE)
