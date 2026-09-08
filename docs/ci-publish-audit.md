# CI 发布与密钥审计（本 fork）

审计对象：`.github/workflows/*`，基线 `6667f35`，本 fork `86669666/CDT-Monitor`。结论：工作流里没有写死的真实密钥；默认发布目标仍是上游生产面，必须先关掉。

## 密钥

| Secret | 使用位置 | 仓库内是否出现明文 | 本 fork 策略 |
| --- | --- | --- | --- |
| `GITHUB_TOKEN` | GHCR login | 否，Actions 注入 | 未开启发布时不 login |
| `DOCKER_USERNAME` / `DOCKER_PASSWORD` | Docker Hub login | 否 | 不要在本 fork 配置；未开启时不 login |
| `ANDROID_KEYSTORE_BASE64` 与 key 密码 | `android-widget.yml` | 否 | 可选；未配置时只出 debug / unsigned 产物 |
| Aliyun AK / SMTP / Telegram | 无 workflow 引用 | 无 | 禁止写入 YAML、Compose 或文档示例 |

引用形式一律是 `${{ secrets.NAME }}` 或 `GITHUB_TOKEN`。不要把 keystore、Docker Hub 密码或云账号写进仓库。
Verify / widget / container / release 的 `actions/checkout` 设置 `persist-credentials: false` 和 `fetch-depth: 1`，避免后续步骤拿到可推送的 `GITHUB_TOKEN`。`Automatic Release` 的 tag job 仍保留凭据，因为它在开启发布时需要 `git push` tag；本 fork 默认不开启。

`GITHUB_TOKEN` 默认只有 `contents: read`。`contents: write` 只给实际打 tag / 写 GitHub Release 的 job，且仍受 `ENABLE_PRODUCTION_PUBLISH` 门闩：

| Job | Token | 何时运行 |
| --- | --- | --- |
| `CI` / widget / container | `contents: read` | 校验路径；不 login、不 push |
| `Automatic Release` `tag` | `contents: write` | 仅发布开启时打 tag |
| `Release Binaries` `frontend` / `build` | `contents: read` | 仅发布开启；artifact 保留 7 天 |
| `Release Binaries` `publish` | `contents: write` | 仅发布开启；写 GitHub Release |
| container caller in `Automatic Release` | `contents: read` | 不申请 `packages: write` |

本 fork 的 Container / Automatic Release 都不申请 `packages: write`。即使误开 `ENABLE_PRODUCTION_PUBLISH`，`GITHUB_TOKEN` 也推不了 GHCR。

第三方 Actions 已按当前 major tag 解析并钉到 commit SHA（注释里保留 `v4`/`v5` 等标签名）。这不开启发布，也不等于远端 CI 已经跑过。
各 job 加了 `timeout-minutes`（verify 20、widget 30、container 60、release 分段 15/20/10），避免一旦 Actions 能跑时挂死占用分钟。

## 镜像名

变更前：

- GHCR：`ghcr.io/${{ github.repository_owner }}/cdt-monitor`（在本 fork 会变成 `ghcr.io/86669666/cdt-monitor`）
- Docker Hub：硬编码 `qninq/cdt-monitor`（上游命名空间，不适合 fork）

变更后：

- GHCR 名称仍随 `repository_owner`；login / push 步骤仍要 `ENABLE_PRODUCTION_PUBLISH=true`，且本 fork 不申请 `packages: write`，误开变量也推不了 GHCR
- `qninq/cdt-monitor` 仅当 `ENABLE_DOCKERHUB_PUBLISH=true` 时写入 metadata
- 本 fork 两个变量都保持未设置

本地开发标签 `ghcr.io/86669666/cdt-monitor:local` 只存在于 [本地 Docker](local-docker.md) 与 `docker-compose.yml`，不会被这个 workflow 推送。

## 触发面

| Workflow | 原行为 | 本 fork |
| --- | --- | --- |
| `CI` | `dev`/`main`/PR | 增加 `work/**` 与 `workflow_dispatch`；concurrency 取消同 ref 旧 run；纯 docs/widget/README 变更跳过 verify。仍不发布 |
| `Automatic Release` | `main` push 自动打 tag 并发布 | 需要 `ENABLE_PRODUCTION_PUBLISH=true`。默认 token 只读；同 ref 并发不取消进行中的 tag/release；不申请 `packages: write` |
| `Release Binaries` | tag / 手动 / 被自动发布调用 | 同上变量，否则整条 job 跳过。前端与二进制 artifact 保留 7 天；只有 `publish` job 拿 `contents: write` |
| `Container Images` | `dev`/tag 构建后 `push: true` | 未开启发布时只做 linux/amd64 load 校验，跳过 QEMU/arm64；push 仍要变量。workflow token 只有 `contents: read`，没有 `packages: write` |
| `Android Widget` | 仅 `workflow_dispatch` | 保持手动；产物是 artifact 不是 registry |

不要把一次绿色 CI 或一次本地 Docker 构建写成已经发布 GHCR / Docker Hub。

## 操作红线

- 不要在 `86669666/CDT-Monitor` 上设置 `ENABLE_PRODUCTION_PUBLISH` 或 `ENABLE_DOCKERHUB_PUBLISH`，除非有单独的发布授权。
- 不要配置 `DOCKER_USERNAME` / `DOCKER_PASSWORD` 去推 `qninq/cdt-monitor`。
- 不要 force-push，不要用本分支做 production deploy。
- Container / Automatic Release workflows 不再申请 `packages: write`。即使误开 `ENABLE_PRODUCTION_PUBLISH`，本 fork 的 GITHUB_TOKEN 也推不了 GHCR，除非有人再把该 permission 加回去。

Dependabot 只跟踪 `github-actions`、根目录 `docker` 和 `/android-widget` 的 Gradle。它会开 PR，不会自动设置 `ENABLE_PRODUCTION_PUBLISH`。合并 Dependabot 前仍要核对 SHA pin，且不要借机打开发布变量。

## 远端质量门（尚未证明）

截至 `2026-09-07T20:50Z`，`gh api repos/86669666/CDT-Monitor/actions/runs` 返回 `total_count: 0`。仓库 Actions 权限 API 为 enabled，但从未观察到 run。

续推证据（`2026-09-07T21:05Z` / 2026-09-08 05:05 Asia/Taipei）：

- 已开 draft PR：https://github.com/86669666/CDT-Monitor/pull/1 （`work/ops` → `main`，head `8d4731e`）
- `statusCheckRollup` 仍为空；`actions/runs` 仍是 0
- `gh workflow list` 为空；`gh workflow run ci.yml --ref work/ops` 返回 404（workflow 实体尚未登记）
- 默认分支 `main` 仍是上游未加发布开关的 `auto-release.yml`。为了“注册 workflow”去合入 `main` 可能触发自动打 tag / GHCR，**不要这样做**

因此远端 CI 记为外部 blocker，不是 YAML 语法问题。candidate SHA 不能写成绿色。下一步只能由能在 GitHub UI 里确认 fork Actions 已真正开始跑的人处理，或由 integration owner 用带 `[skip release]` 的受控合入。不要设置发布变量，不要打生产 tag。

续推证据（`2026-09-08T04:41Z` / 2026-09-08 12:41 Asia/Taipei）：

- `actions/runs` 仍是 `total_count: 0`
- `gh workflow list` 仍为空；仓库 Actions variables 为 `total_count: 0`（`ENABLE_PRODUCTION_PUBLISH` / `ENABLE_DOCKERHUB_PUBLISH` 未设置）
- draft PR https://github.com/86669666/CDT-Monitor/pull/1 仍开着；不要把 contents 权限收口或 artifact 7 天过期写成远端 CI 已绿或已经发布 GHCR
