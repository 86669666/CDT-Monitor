# CI 发布与密钥审计（本 fork）

审计对象：`.github/workflows/*`，基线 `6667f35`，本 fork `86669666/CDT-Monitor`。结论：工作流里没有写死的真实密钥；默认发布目标仍是上游生产面，必须先关掉。

## 密钥

| Secret | 使用位置 | 仓库内是否出现明文 | 本 fork 策略 |
| --- | --- | --- | --- |
| `GITHUB_TOKEN` | 曾用于 GHCR login | 否，Actions 注入 | Container Images 已删除 login 步骤，不再把 token 交给 GHCR |
| `DOCKER_USERNAME` / `DOCKER_PASSWORD` | 曾用于 Docker Hub login | 否 | 不要在本 fork 配置；Container Images 已删除 login 步骤，YAML 不再引用这两个 secret |
| `ANDROID_KEYSTORE_BASE64` 与 key 密码 | `android-widget.yml` | 否 | 可选；未配置时只出 debug / unsigned 产物。解码后的 JKS 只在 `$RUNNER_TEMP`（`chmod 600`），job `always()` 里 shred/rm，不进 artifact |
| Aliyun AK / SMTP / Telegram | 无 workflow 引用 | 无 | 禁止写入 YAML、Compose 或文档示例 |

引用形式一律是 `${{ secrets.NAME }}` 或 `GITHUB_TOKEN`。不要把 keystore、Docker Hub 密码或云账号写进仓库。
Verify / widget / container / release 的 `actions/checkout` 设置 `persist-credentials: false` 和 `fetch-depth: 1`，避免后续步骤拿到可推送的 `GITHUB_TOKEN`。`Automatic Release` 的 tag job 仍保留凭据，因为它在开启发布时需要 `git push` tag；本 fork 默认不开启。

`GITHUB_TOKEN` 默认只有 `contents: read`。`contents: write` 只给实际打 tag / 写 GitHub Release 的 job，且仍受 `ENABLE_PRODUCTION_PUBLISH` 门闩：

| Job | Token | 何时运行 |
| --- | --- | --- |
| `CI` / widget / container | `contents: read` | 校验路径；不 login、不 push |
| `Automatic Release` `tag` | `contents: write` | 仅发布开启时打 tag；`fetch-depth: 1`（版本来自 dispatch 输入，不再为列 tag 拉全历史） |
| `Release Binaries` `frontend` / `build` | `contents: read` | 仅发布开启；artifact 保留 7 天 |
| `Release Binaries` `publish` | `contents: write` | 仅发布开启；只写 **draft** GitHub Release，且 `make_latest: false` |
| container caller in `Automatic Release` | `contents: read` | 不申请 `packages: write` |

本 fork 的 Container / Automatic Release 都不申请 `packages: write`。即使误开 `ENABLE_PRODUCTION_PUBLISH`，`GITHUB_TOKEN` 也推不了 GHCR。

第三方 Actions 已按当前 major tag 解析并钉到 commit SHA（注释里保留 `v4`/`v5` 等标签名）。这不开启发布，也不等于远端 CI 已经跑过。
各 job 加了 `timeout-minutes`（verify 20、widget 20、container amd64 verify 20、release 分段 15/20/10），避免一旦 Actions 能跑时挂死占用分钟。

## 镜像名

变更前：

- GHCR：`ghcr.io/${{ github.repository_owner }}/cdt-monitor`（在本 fork 会变成 `ghcr.io/86669666/cdt-monitor`）
- Docker Hub：硬编码 `qninq/cdt-monitor`（上游命名空间，不适合 fork）

变更后：

- Container Images 不再运行 `docker/login-action`，也不再给 `ghcr.io/<owner>/cdt-monitor` 或 `qninq/cdt-monitor` 写 metadata。runner 只 load 本地标签 `cdt-monitor:verify-amd64`，且 `push: false`
- 不申请 `packages: write`。误开 `ENABLE_PRODUCTION_PUBLISH` / `ENABLE_DOCKERHUB_PUBLISH` 也不会 login 或推仓库
- 本 fork 两个变量都保持未设置

本地开发标签 `cdt-monitor:local` 只存在于 [本地 Docker](local-docker.md) 与 `docker-compose.yml`（无 GHCR/Hub 前缀），不会被这个 workflow 推送。Dockerfile 默认 `IMAGE_SOURCE` 与 Compose 均为本 fork；Container Images 的 amd64 verify 传入 `IMAGE_SOURCE=https://github.com/${{ github.repository }}`，仍只 load 本地 `cdt-monitor:verify-amd64`。

## 触发面

| Workflow | 原行为 | 本 fork |
| --- | --- | --- |
| `CI` | `dev`/`main`/PR | 增加 `work/**` 与 `workflow_dispatch`；concurrency 取消同 ref 旧 run；纯 docs/widget/README/compose/dockerignore、Dependabot、`android-widget.yml` 或其它发布 workflow YAML 变更跳过 verify。仍不发布 |
| `Automatic Release` | `main` push 自动打 tag 并发布 | 不再因 `main` push 自动跑。仅 `workflow_dispatch`，且需要 `ENABLE_PRODUCTION_PUBLISH=true`。不把仓库 secrets inherit 进 reusable workflows。默认 token 只读；同 ref 并发不取消进行中的 tag/release；不申请 `packages: write` |
| `Release Binaries` | 仅手动或被 auto-release `workflow_call` | 不再因 `v*.*.*` tag push 自动跑。仍要 `ENABLE_PRODUCTION_PUBLISH`；本 fork 只编 linux/amd64；artifact 保留 7 天；只有 `publish` job 拿 `contents: write`，且 `draft: true`、`make_latest: false`、`generate_release_notes: false` |
| `Container Images` | 仅手动或被 auto-release `workflow_call` | 不再因 `dev`/tag push 自动跑。文件里已删除 login / GHCR·Hub metadata / QEMU / arm64 / multi-arch；Buildx `driver: docker`；只 load 校验 linux/amd64，`push: false`，`provenance: false`，`sbom: false`，无 `type=gha` cache；`version` 检查用 `--network none --read-only --user 65532`；没有 `packages: write`。Publish Guard 禁止把 `on.push` / `v*.*.*` tag 触发加回来，并要求 Dockerfile 默认 `IMAGE_SOURCE` 仍是本 fork |
| `Android Widget` | 仅 `workflow_dispatch` | 保持手动；产物是 artifact 不是 registry |
| `Publish Guard` | 无（本 fork 新增） | `dev`/`main`/`work/**` push、PR、手动。只跑 `.github/scripts/assert-no-publish.sh`：发布变量不能为 true；workflow YAML 不能恢复 `packages: write` / login / Hub 名 / `secrets: inherit` / `push: true`；Compose `image:` 必须是无仓库前缀的 `cdt-monitor:local`，端口必须是 `127.0.0.1:43210:8080`，环境里不能有 AK/通知密钥/`CDT_TRUSTED_PROXIES`。不 login、不 push |

不要把一次绿色 CI 或一次本地 Docker 构建写成已经发布 GHCR / Docker Hub。

## 操作红线

- 不要在 `86669666/CDT-Monitor` 上设置 `ENABLE_PRODUCTION_PUBLISH` 或 `ENABLE_DOCKERHUB_PUBLISH`，除非有单独的发布授权。
- 不要配置 `DOCKER_USERNAME` / `DOCKER_PASSWORD`，也不要把 `docker/login-action`、GHCR/Hub 镜像名、`qninq/cdt-monitor` 或 provenance/SBOM 加回 Container Images。
- 不要 force-push，不要用本分支做 production deploy。
- Container / Automatic Release workflows 不再申请 `packages: write`。即使误开 `ENABLE_PRODUCTION_PUBLISH`，本 fork 的 GITHUB_TOKEN 也推不了 GHCR，除非有人再把该 permission 加回去。
- 不要给 `Automatic Release` 加回 `main`/`dev`/tag 的 `on.push`，也不要把 `secrets: inherit` 加回它调用的 reusable workflows。
- 不要把 Release Binaries 的 `draft: true` 改成正式发布，也不要把 `make_latest` 或 `generate_release_notes` 打开，除非有单独的发布授权。
- 不要把 Release Binaries 的 GOOS/GOARCH matrix 从 linux/amd64 扩回去，除非有单独的发布授权。
- 不要删掉 `Publish Guard` 或 `.github/scripts/assert-no-publish.sh`，也不要从 Automatic Release 的 `tag` / `release` / `container` 三个 job 上拿掉 `ENABLE_PRODUCTION_PUBLISH` 门闩。
- 不要把 Compose 端口改成 `0.0.0.0` 或省略 `127.0.0.1`；Publish Guard 会把它当成发布面回归。
- CI `paths-ignore` 仍会跳过发布 workflow / guard 脚本的纯 YAML 变更，因此 Publish Guard 必须单独跑；不要把这些路径加回昂贵的 Go verify 来代替这个扫描。

Dependabot 只跟踪 `github-actions`、根目录 `docker` 和 `/android-widget` 的 Gradle。同类更新打成一组 PR（actions / docker base / widget Gradle 各一组），减少噪声。`target-branch` 是 `work/ops`，避免 bump PR 默认打到仍带未加开关 `auto-release.yml` 的 `main`。它会开 PR，不会自动设置 `ENABLE_PRODUCTION_PUBLISH`。合并 Dependabot 前仍要核对 SHA pin，且不要借机打开发布变量。GitHub 只从默认分支读这个文件；不要为了启用 Dependabot 去合 `main`。

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

续推证据（`2026-09-08T06:37Z` / 2026-09-08 14:37 Asia/Taipei），对象 `86669666/CDT-Monitor`，基线仍是 `6667f35`，当时 HEAD `5c08e78`：

- `gh api repos/86669666/CDT-Monitor/actions/runs` 仍是 `total_count: 0`；`actions/workflows` 仍是 `total_count: 0`
- `gh workflow list --repo 86669666/CDT-Monitor --all` 为空；`gh workflow run ci.yml --repo 86669666/CDT-Monitor --ref work/ops` 仍是 404
- Actions 权限 API：`enabled=true`，`default_workflow_permissions=read`；variables `total_count: 0`；`gh secret list --repo 86669666/CDT-Monitor` 为空
- draft PR https://github.com/86669666/CDT-Monitor/pull/1 仍为 draft，当时 head `5c08e78`，`statusCheckRollup` 为空
- 不要用无 `--repo 86669666/CDT-Monitor` 的 `gh workflow list` / `gh run list`：此工作区有 `upstream` remote 时，GitHub CLI 会落到 `wang4386/CDT-Monitor`，那些 run 不是本 fork 的证据
- 默认分支 `main` 仍是上游未加发布开关、且仍 `packages: write` 的 `auto-release.yml`。为了“注册 workflow”去合入 `main` 可能触发自动打 tag / GHCR，**不要这样做**

续推证据（`2026-09-08T06:51Z` / 2026-09-08 14:51 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `3b2f466`：

- `actions/runs` / `actions/workflows` 仍是 `total_count: 0`；`gh workflow run` 仍会 404
- Container Images 删除 GHCR/Hub login 与 registry metadata 之后，该 YAML 不再引用 `DOCKER_USERNAME` / `DOCKER_PASSWORD` / `GITHUB_TOKEN` login
- 不要把这次 YAML 收缩写成远端 CI 已绿或已经发布

续推证据（`2026-09-08T16:45Z` / 2026-09-09 00:45 Asia/Taipei），对象 `86669666/CDT-Monitor`，基线仍是 `6667f35`，当时 HEAD `4328d23`：

- `gh api repos/86669666/CDT-Monitor/actions/runs` 仍是 `total_count: 0`；`actions/workflows` 仍是 `total_count: 0`
- `gh workflow run ci.yml --repo 86669666/CDT-Monitor --ref work/ops` 仍是 404
- Actions 权限 API：`enabled=true`，`allowed_actions=all`，`default_workflow_permissions=read`；variables `total_count: 0`；`gh secret list --repo 86669666/CDT-Monitor` 为空（`ENABLE_PRODUCTION_PUBLISH` / `ENABLE_DOCKERHUB_PUBLISH` 未设置）
- draft PR https://github.com/86669666/CDT-Monitor/pull/1 仍为 draft，当时 head `4328d23`，`statusCheckRollup` 为空
- 查询必须带 `--repo 86669666/CDT-Monitor`。无 `--repo` 的 `gh` 会落到 `wang4386/CDT-Monitor`，那些 run 不是本 fork 的证据
- 默认分支 `origin/main` 仍是上游未加发布开关、且 `permissions: contents: write` + `packages: write` 的 `auto-release.yml`（`on.push.branches: [main]`）。为了“注册 workflow”去合入 `main` 可能触发自动打 tag / GHCR，**不要这样做**
- 本分支后续的 draft / `make_latest: false` / Dependabot `work/ops` / 本地 `cdt-monitor:local` 标签都不等于远端 CI 已绿，也不等于已经发布

续推证据（`2026-09-08T17:46Z` / 2026-09-09 01:46 Asia/Taipei），对象 `86669666/CDT-Monitor`，基线仍是 `6667f35`，当时 HEAD `f2d065f`：

- `gh api repos/86669666/CDT-Monitor/actions/runs` 仍是 `total_count: 0`；`actions/workflows` 仍是 `total_count: 0`
- `gh workflow run ci.yml --repo 86669666/CDT-Monitor --ref work/ops` 仍是 404
- Actions 权限 API：`enabled=true`，`allowed_actions=all`，`sha_pinning_required=false`，`default_workflow_permissions=read`；variables `total_count: 0`；`gh secret list --repo 86669666/CDT-Monitor` 为空
- draft PR https://github.com/86669666/CDT-Monitor/pull/1 仍为 draft，当时 head `f2d065f`，`statusCheckRollup` 为空
- `origin/main` 仍是上游未加发布开关、且 `packages: write` 的 `auto-release.yml`。**不要**为了登记 workflow 合入 `main`
- 本分支后来的 linux/amd64-only Release、container `--network none` verify、widget `sdkDownload=false` / `networkTimeout=120000` 都不等于远端 CI 已绿，也不等于已经发布

续推证据（`2026-09-09T17:35Z` / 2026-09-10 01:35 Asia/Taipei），对象 `86669666/CDT-Monitor`，基线仍是 `6667f35`，当时 HEAD `a0d941d` 再加本轮 Publish Guard：

- Actions 已登记 **CI**（id `354235773`）。`gh api repos/86669666/CDT-Monitor/actions/workflows` 仍只有这一条；Automatic Release / Release Binaries / Container Images / Android Widget / Publish Guard 都还没出现在 default-branch 列表里
- PR https://github.com/86669666/CDT-Monitor/pull/2 （`work/integration` → `main`）上 `CI / verify` 为 **success**（runs `34381859970` PR、`34381859313` push）。这是本 fork 第一次观察到的绿色 verify，不是 GHCR / GitHub Release / widget 已跑
- draft PR https://github.com/86669666/CDT-Monitor/pull/1 已关闭（superseded by PR#2）。不要重新打开它来“登记 workflow”
- 仓库 Actions variables 仍是 `total_count: 0`；`gh secret list --repo 86669666/CDT-Monitor` 仍为空；`ENABLE_PRODUCTION_PUBLISH` / `ENABLE_DOCKERHUB_PUBLISH` 未设置
- Actions 权限 API：`enabled=true`，`allowed_actions=all`，`sha_pinning_required=false`，`default_workflow_permissions=read`
- `origin/main` 仍是上游未加发布开关、且 `packages: write` + `secrets: inherit` 的 `auto-release.yml`（`on.push.branches: [main]`）。**不要**为了登记 Publish Guard 或 Dependabot 把未加开关的 `main` 工作流留着合入；替换它是 integration 把已加开关的 PR#2 合进 `main` 的事，ops 不合 `main`
- 本轮在 `work/ops` 给 Automatic Release 的 `release` / `container` caller 补了独立的 `ENABLE_PRODUCTION_PUBLISH` 门闩，并新增 Publish Guard。本地已跑 `bash .github/scripts/assert-no-publish.sh`。这仍不是 GHCR 发布，也不是 widget / Container Images workflow 已登记

续推证据（`2026-09-09T18:26Z` / 2026-09-10 02:26 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `89ebdbf` 再加 Compose loopback 扫描：

- Publish Guard 现检查 `docker-compose.yml` 必须发布 `127.0.0.1:43210:8080`，且环境里不能出现 `CDT_MASTER_KEY` / `CDT_TRUSTED_PROXIES` / AK 或通知密钥。这锁的是本机绑定，不是 `CDT_TRUSTED_PROXIES` 已经实现
- `origin/main` 仍是未加开关的 Automatic Release。不要把这次扫描写成 PR#2 可以合进 `main`
- 仓库 Actions variables 仍应保持未设置；本轮没有打开 `ENABLE_PRODUCTION_PUBLISH`

续推证据（`2026-09-09T18:46Z` / 2026-09-10 02:46 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `5d86323` 再加 Dockerfile/source 与 container `on.push` 扫描：

- Publish Guard 现要求 Dockerfile 默认 `IMAGE_SOURCE=https://github.com/86669666/CDT-Monitor`，且 Container Images YAML 不能恢复 `on.push` / `v*.*.*` tag 触发
- 这仍只是 load-verify，不是 GHCR 发布，也不是把 PR#2 合进未加开关 `main` 的许可
