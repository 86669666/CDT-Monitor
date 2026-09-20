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
Verify / widget / container / release 的 `actions/checkout` 设置 `persist-credentials: false` 和 `fetch-depth: 1`，避免后续步骤拿到可推送的 `GITHUB_TOKEN`。`Automatic Release` 的 tag job 仍保留凭据，因为它在开启发布时需要 `git push` tag；本 fork 默认不开启。Publish Guard 会拒绝在其它 workflow 里把 `persist-credentials: true` 加回来。

`GITHUB_TOKEN` 默认只有 `contents: read`。`contents: write` 只给实际打 tag / 写 GitHub Release 的 job，且仍受 `ENABLE_PRODUCTION_PUBLISH` 门闩：

| Job | Token | 何时运行 |
| --- | --- | --- |
| `CI` / widget / container | `contents: read` | 校验路径；不 login、不 push |
| `Automatic Release` `tag` | `contents: write` | 仅发布开启时打 tag；`fetch-depth: 1`（版本来自 dispatch 输入，不再为列 tag 拉全历史） |
| `Release Binaries` `frontend` / `build` | `contents: read` | 仅发布开启；artifact 保留 7 天 |
| `Release Binaries` `publish` | `contents: write` | 仅发布开启；只写 **draft** GitHub Release，且 `make_latest: false` |
| container caller in `Automatic Release` | `contents: read` | 不申请 `packages: write` |

本 fork 的 Container / Automatic Release 都不申请 `packages: write`。即使误开 `ENABLE_PRODUCTION_PUBLISH`，`GITHUB_TOKEN` 也推不了 GHCR。

第三方 Actions 已按当前 major tag 解析并钉到 commit SHA（注释里保留 `v4`/`v5` 等标签名）。Publish Guard 会拒绝 `uses: ...@v4` 这种浮动标签（本地 `./.github/workflows/*` 除外），并要求 checkout `fetch-depth: 1`。这不开启发布，也不等于远端 CI 已经跑过。
各 job 加了 `timeout-minutes`（verify 20、widget 20、container amd64 verify 20、release 分段 15/20/10），避免一旦 Actions 能跑时挂死占用分钟。Reusable caller 不能设 `timeout-minutes`（GitHub 会把 workflow 判成无效）；超时仍在被调用的 job 上。Publish Guard 要求每个 `runs-on` job 都有超时，且 `contents: write` / `id-token: write` 不能出现在 CI / widget / container verify / Publish Guard 里。

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

续推证据（`2026-09-09T19:06Z` / 2026-09-10 03:06 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `d5f9913` 再加 checkout 凭据扫描与 gated job 名称：

- Automatic Release / Release Binaries 的 job 名称标明 gated；Publish Guard 禁止在 tag job 以外使用 `persist-credentials: true`
- 这仍不是已经打 tag 或写 GitHub Release，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-09T19:46Z` / 2026-09-10 03:46 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `ff17286` 再加 job timeout / contents:write 扫描：

- Publish Guard 现要求每个 `runs-on` job 都有 `timeout-minutes`，并禁止在 CI / widget / container verify 上使用 `contents: write` 或 `id-token: write`
- GitHub 拒绝在 `uses:` caller 上写 `timeout-minutes`（run 34397202388 无 job 即失败）；已撤回 caller 超时，只保留 `runs-on` job 的超时扫描。这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-09T19:50Z` / 2026-09-10 03:50 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `8c7805a` 再加 action SHA pin / fetch-depth 扫描：

- Publish Guard 现要求第三方 `uses:` 钉死 40 位 SHA，checkout 必须 `fetch-depth: 1`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-15T21:36Z` / 2026-09-16 05:36 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `3d82962` 再加 Release Binaries concurrency / artifact 7 天扫描：

- Release Binaries 补了 top-level `concurrency`（`cancel-in-progress: false`，避免误 dispatch 取消进行中的 gated build）
- Publish Guard 现要求每个 workflow 都有 `concurrency` 与 top-level `permissions`，且 `upload-artifact` 必须 `retention-days: 7`
- `origin/main` 仍是未加开关的 Automatic Release。这仍不是已经发布，也不是 PR#2 可以合进 `main`

续推证据（`2026-09-15T21:50Z` / 2026-09-16 05:50 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `83fb0ca` 再加 Compose `pull_policy: build` 与 `docker push` 扫描：

- Publish Guard 现要求 Compose 保持 `pull_policy: build`，workflow `run` 里不能出现 `docker push` / `compose push`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-15T22:01Z` / 2026-09-16 06:01 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `57993b6` 再加 concurrency cancel 策略扫描：

- Publish Guard 现要求 Automatic Release / Release Binaries 保持 `cancel-in-progress: false`，CI / widget / container / Publish Guard 保持 `true`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-15T22:18Z` / 2026-09-16 06:18 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `7926775` 再加 workflow-level contents:read 扫描：

- Publish Guard 现要求每个 workflow 顶层 `permissions.contents` 为 `read`，禁止顶层 `contents: write` / `packages:`
- `origin/main` 的 Automatic Release 仍是顶层 `contents: write` + `packages: write`。不要为了登记 workflow 把那份 YAML 合进 `main`

续推证据（`2026-09-15T22:36Z` / 2026-09-16 06:36 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `870269b` 再加 Compose 权限面扫描：

- Publish Guard 现要求 Compose 保持 `privileged: false`、`cap_drop: ALL`、`no-new-privileges`、`read_only`、`user 65532:65532`、`restart: on-failure`（禁止 `unless-stopped`）
- 这锁的是本机容器权限面，不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-15T22:52Z` / 2026-09-16 06:52 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `10ed635` 再加 dockerignore / 非 root USER 扫描：

- Publish Guard 现要求 Dockerfile `USER 65532:65532`，且 `.dockerignore` 必须排除 `.github`、`android-widget`、`.env`、keystore、`master.key`、SQLite 和 `docs`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-15T22:58Z` / 2026-09-16 06:58 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `c640231` 再加 Dependabot target-branch 扫描：

- Publish Guard 现要求三个 ecosystem 都 `target-branch: work/ops`，禁止指向 `main`；workflow 里的 `npm ci` 必须带 `--ignore-scripts`
- GitHub 只从默认分支读 Dependabot；不要为了启用它去合未加开关的 `main`

续推证据（`2026-09-15T23:16Z` / 2026-09-16 07:16 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `7b02aaa` 再加 Dockerfile digest / scratch 扫描：

- Publish Guard 现要求最终 `FROM scratch`、digest-pinned 基础镜像、`HEALTHCHECK`、`EXPOSE 8080`，禁止 `:latest`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-15T23:31Z` / 2026-09-16 07:31 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `f927018` 再加 CI verify 命令扫描：

- Publish Guard 现要求 CI job 名 `Verify (no publish)`，Go 1.24 / Node 22，`go test -race`、`go vet`、`CGO_ENABLED=0 linux/amd64`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-15T23:45Z` / 2026-09-16 07:45 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `944e1ef` 再加 container load-verify 扫描：

- Publish Guard 现要求 Container Images 保持 `driver: docker`、`load: true`、`push: false`、无 QEMU、`linux/amd64`，以及 `docker run --network none --read-only --user 65532`
- 这仍不是 GHCR 发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-15T23:50Z` / 2026-09-16 07:50 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `8233562` 再加 widget dispatch-only 扫描：

- Publish Guard 现要求 Android Widget 仅 `workflow_dispatch`、JDK 17、20 分钟超时、job 名 artifact only，禁止 Play 上传；Container Images 禁止 `type=gha` / `cache-to`
- 这仍不是 widget 已跑或已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-15T23:55Z` / 2026-09-16 07:55 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `ed650f8` 再加 widget keystore shred 扫描：

- Publish Guard 现要求 Android Widget 用 `secrets.ANDROID_KEYSTORE_BASE64`、`umask 077`、写在 `$RUNNER_TEMP`，并在 `if: always()` 里 `shred`
- 仓库 secrets 仍为空。这仍不是 APK 已构建，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T00:06Z` / 2026-09-16 08:06 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `1fbd22c` 再加 Compose tmpfs/healthcheck 扫描：

- Publish Guard 现要求 `/tmp` tmpfs 为 `noexec,nosuid,nodev`，healthcheck 为 `/cdt-monitor healthcheck`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T00:25Z` / 2026-09-16 08:25 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `c7dac31` 再加 production environment / pipe-to-shell 扫描：

- Publish Guard 现禁止 workflow `environment: production` 与 `curl|sh` / `wget|sh`，并要求 Dockerfile `# syntax=` 前端钉 SHA
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T00:43Z` / 2026-09-16 08:43 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `b992d66` 再加 widget wrapper-validation 扫描：

- Publish Guard 现要求 Android Widget 使用同一 SHA 的 `wrapper-validation` 与 `setup-gradle`，并保持 `assembleDebug assembleRelease bundleRelease`
- 这仍不是 APK 已构建，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T00:53Z` / 2026-09-16 08:53 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `6defbaa` 再加 extra write permissions 扫描：

- Publish Guard 现禁止 `actions: write`、`pull-requests: write`、`attestations: write`、`security-events: write`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T00:58Z` / 2026-09-16 08:58 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `5b931f8` 再加 STOPSIGNAL / log cap 扫描：

- Publish Guard 现要求 Dockerfile `STOPSIGNAL SIGTERM`、`ENTRYPOINT /cdt-monitor`、`CMD serve`，以及 Compose json-file `max-size: 10m` × `max-file: 3`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T01:04Z` / 2026-09-16 09:04 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `44b6b6e` 再加 widget --no-daemon / sdk licenses 扫描：

- Publish Guard 现要求 `./gradlew --no-daemon`、非交互 `sdkmanager --licenses`、以及 `platforms;android-35`
- 这仍不是 APK 已构建，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T01:21Z` / 2026-09-16 09:21 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `1a54ecc` 再加 Compose init/limits/TZ 扫描：

- Publish Guard 现要求 `init: true`、`pids_limit: 256`、`mem_limit: 512m`、`cpus: 1.0`、`CDT_LISTEN: :8080`、`TZ: Asia/Taipei`、`stop_grace_period: 15s`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T01:27Z` / 2026-09-16 09:27 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `6729f1a` 再加 linux/amd64-only Release matrix 扫描：

- Publish Guard 现要求 Release Binaries 只有 `{ goos: linux, goarch: amd64 }`，禁止 windows/darwin/arm，publish job 名保持 draft / not latest
- 这仍不是已经打 GitHub Release，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T01:37Z` / 2026-09-16 09:37 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `2bd87cb` 再加 auto-release version regex 扫描：

- Publish Guard 现要求 Automatic Release 的 tag job 名 `Create tag (gated)`、版本必须匹配 `vMAJOR.MINOR.PATCH`、tagger 为 `github-actions[bot]`
- 这仍不是已经打 tag，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T01:48Z` / 2026-09-16 09:48 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `12c29c1` 再加 Compose stop_signal/memswap/data 扫描：

- Publish Guard 现要求 `stop_signal: SIGTERM`、`memswap_limit: 512m`、`CDT_DATA_DIR: /data`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T02:01Z` / 2026-09-16 10:01 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `51c54b7` 再加 widget temurin / gradle cache cleanup 扫描：

- Publish Guard 现要求 `distribution: temurin` 与 `gradle-home-cache-cleanup: true`
- 这仍不是 APK 已构建，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T02:08Z` / 2026-09-16 10:08 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `9da70b5` 再加 CI npm run build 扫描：

- Publish Guard 现要求 CI 在 `web/` 里 `npm run build`，并用 `web/package-lock.json` 做 npm cache
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T02:12Z` / 2026-09-16 10:12 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `c08ae19` 再加 Compose named volume cdt-data 扫描：

- Publish Guard 现要求 named volume `cdt-data:/data`，禁止把宿主机 `./data` bind-mount 进容器
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T02:28Z` / 2026-09-16 10:28 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `227be06` 再加 CI go build ./cmd/cdt-monitor 扫描：

- Publish Guard 现要求 CI `go build -trimpath ./cmd/cdt-monitor`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T02:35Z` / 2026-09-16 10:35 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `2704b6b` 再加 Dockerfile HEALTHCHECK command 扫描：

- Publish Guard 现要求 HEALTHCHECK 为 `30s/5s/10s/3` 且命令 `/cdt-monitor healthcheck`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T02:50Z` / 2026-09-16 10:50 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `039aade` 再加 Dockerfile VOLUME /data chown 扫描：

- Publish Guard 现要求 `VOLUME ["/data"]` 且 `/runtime-data` 以 `--chown=65532:65532` 复制
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T02:59Z` / 2026-09-16 10:59 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `4bbd7e2` 再加 widget artifact paths 扫描：

- Publish Guard 现要求 widget artifact 只包含 debug/release APK 与 AAB，禁止把 `.jks` / `.keystore` 打进 artifact
- 这仍不是 APK 已构建，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T03:11Z` / 2026-09-16 11:11 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `85e6eed` 再加 Compose project/container name 扫描：

- Publish Guard 现要求 Compose `name: cdt-monitor`、`container_name: cdt-monitor`、`CDT_WORKERS: 2`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T03:20Z` / 2026-09-16 11:20 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `e2e64a8` 再加 Dockerfile ca-certificates 扫描：

- Publish Guard 现要求 scratch 镜像复制 `ca-certificates.crt`（HTTPS 出站，不是入站 TLS/HSTS）
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T03:27Z` / 2026-09-16 11:27 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `69853a2` 再加 Dockerfile npm ci --ignore-scripts 扫描：

- Publish Guard 现要求镜像前端 `npm ci --ignore-scripts` + `npm run build`，Go 侧 `CGO_ENABLED=0 ./cmd/cdt-monitor`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T03:30Z` / 2026-09-16 11:30 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `9a7bdfe` 再加 widget working-directory / setup-android 扫描：

- Publish Guard 现要求 `working-directory: android-widget` 与 `android-actions/setup-android`
- 这仍不是 APK 已构建，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T03:40Z` / 2026-09-16 11:40 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `5befbec` 再加 Compose/Dockerfile 80/443 扫描：

- Publish Guard 现禁止把宿主机 80/443 映射进 Compose，也禁止 Dockerfile `EXPOSE 80/443`。TLS/HSTS 仍在反向代理，应用只听 8080 / loopback 43210
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T03:45Z` / 2026-09-16 11:45 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `e559e5f` 再加 Dockerfile TARGETOS/TARGETARCH 扫描：

- Publish Guard 现要求 `ARG TARGETOS` / `ARG TARGETARCH` 不带默认值，编译用 `GOOS=${TARGETOS} GOARCH=${TARGETARCH}`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T03:59Z` / 2026-09-16 11:59 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `ab3ca2f` 再加 Dockerfile BUILDPLATFORM 扫描：

- Publish Guard 现要求 node/go/alpine 阶段 `--platform=$BUILDPLATFORM`，最终 `FROM scratch` 不钉 platform
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T04:20Z` / 2026-09-16 12:20 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `e12a4cf` 再加 Dockerfile COPY --from=frontend dist 扫描：

- Publish Guard 现要求嵌入 UI 来自 frontend 阶段 `internal/web/dist`，二进制来自 builder，而不是宿主机预提交的 dist
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T04:30Z` / 2026-09-16 12:30 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `b58361f` 再加 Dockerfile lockfile COPY 扫描：

- Publish Guard 现要求先 COPY `package-lock.json` / `go.mod` `go.sum`，再 `npm ci` / `go mod download`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T04:39Z` / 2026-09-16 12:39 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `a8be68b` 再加 Dockerfile stage names 扫描：

- Publish Guard 现要求阶段名 `AS frontend` / `AS builder` / `AS certificates`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T04:49Z` / 2026-09-16 12:49 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `6076872` 再加 OCI source/licenses LABEL 扫描：

- Publish Guard 现要求 `org.opencontainers.image.source` 使用 `IMAGE_SOURCE`，`licenses` 为 MIT
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T04:58Z` / 2026-09-16 12:58 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `3640a49` 再加 Dockerfile -trimpath/-ldflags 扫描：

- Publish Guard 现要求镜像 Go 编译带 `-trimpath`、`-ldflags -s -w`、以及 `-X main.version=${VERSION}`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T05:08Z` / 2026-09-16 13:08 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `62567fb` 再加 Dockerfile WORKDIR/runtime-data 扫描：

- Publish Guard 现要求 `WORKDIR /src/web`、`WORKDIR /src`、以及 `mkdir -p /runtime-data`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T05:17Z` / 2026-09-16 13:17 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `0854a32` 再加 Compose IMAGE_SOURCE fork URL 扫描：

- Publish Guard 现要求 Compose build-arg `IMAGE_SOURCE: https://github.com/86669666/CDT-Monitor`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T05:29Z` / 2026-09-16 13:29 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `a83b758` 再加 Dockerfile COPY web ./ 扫描：

- Publish Guard 现要求 frontend `COPY web ./`、builder `COPY . ./`（lockfile 之后）
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T05:39Z` / 2026-09-16 13:39 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `43616f4` 再加 Dockerfile -o /cdt-monitor 扫描：

- Publish Guard 现要求 `go build -o /cdt-monitor`，与 scratch `COPY --from=builder /cdt-monitor` 对齐
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T05:54Z` / 2026-09-16 13:54 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `5270ee6` 再加 Dockerfile no ADD / no USER root 扫描：

- Publish Guard 现禁止 `ADD` 与 `USER root`/`USER 0`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T06:17Z` / 2026-09-16 14:17 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `77354d0` 再加 Compose host namespace 扫描：

- Publish Guard 现禁止 `network_mode: host`、`pid: host`、`ipc: host`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T06:30Z` / 2026-09-16 14:30 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `e44e6d7` 再加 Compose cap_add/devices/sysctls 扫描：

- Publish Guard 现禁止 `cap_add`、`devices`、`sysctls`（保持 `cap_drop: ALL`）
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T06:38Z` / 2026-09-16 14:38 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `e976c9e` 再加 Compose extra_hosts/tty 扫描：

- Publish Guard 现禁止 `extra_hosts`、`stdin_open: true`、`tty: true`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T06:49Z` / 2026-09-16 14:49 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `e960ed3` 再加 Dockerfile apk-only CA 扫描：

- Publish Guard 现禁止 apt/yum/dnf，且只允许一次 `apk add --no-cache ca-certificates`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T06:54Z` / 2026-09-16 14:54 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `d8235bf` 再加 Dockerfile VERSION/COMMIT/BUILT_AT 默认值扫描：

- Publish Guard 现要求 `ARG VERSION=dev`、`COMMIT=unknown`、`BUILT_AT=unknown`，本地构建不必 docker login 填版本
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T07:25Z` / 2026-09-16 15:25 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `1cb7745` 再加 Compose 单服务 / 本地标签扫描：

- Publish Guard 现要求 `services:` 里只有 `cdt-monitor`，且唯一 `image:` 仍是无仓库前缀的 `cdt-monitor:local`。不要在 Compose 里加 nginx/caddy/traefik sidecar；HSTS/TLS 仍在外部反向代理
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T07:30Z` / 2026-09-16 15:30 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `8831163` 再加危险 workflow 触发扫描：

- Publish Guard 现禁止 `pull_request_target`、`workflow_run`、`repository_dispatch` 和 `permissions: write-all`。fork PR 不得拿到 base 仓库权限，也不要靠 workflow_run 把 secrets 带到不可信代码
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T07:35Z` / 2026-09-16 15:35 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `7593d7e` 再加 Compose env_file/command 扫描：

- Publish Guard 现禁止 Compose `env_file`、`command`、`entrypoint`。不要用宿主机 `.env` 把 AK 绕过 YAML 扫描，也不要覆盖镜像 `/cdt-monitor serve`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T07:47Z` / 2026-09-16 15:47 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `db28949` 再加 ubuntu-latest / 禁止 self-hosted 扫描：

- Publish Guard 现要求每个 `runs-on` 仍是 GitHub-hosted `ubuntu-latest`，禁止 `self-hosted`。不要把 fork 的 CI 放到自建 runner 上
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T08:01Z` / 2026-09-16 16:01 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `8071a4c` 再加 Compose networks/expose 扫描：

- Publish Guard 现禁止 Compose `networks`、`expose`、`depends_on` 和 `external: true`。发布面只留 loopback `127.0.0.1:43210`，数据卷仍是本地 `cdt-data`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T08:10Z` / 2026-09-16 16:10 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `b0f1a7e` 再加 continue-on-error / toJSON(secrets) 扫描：

- Publish Guard 现禁止 `continue-on-error: true` 和 `toJSON(secrets)`。不要把校验失败吞掉，也不要把仓库 secret 图打进日志
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T08:19Z` / 2026-09-16 16:19 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `1d203a6` 再加 Dockerfile curl/ONBUILD/SHELL 扫描：

- Publish Guard 现禁止 Dockerfile 里的 `curl`/`wget`、`ONBUILD` 和 `SHELL`。CA 仍只走一次 `apk add --no-cache ca-certificates`，不要再加管道安装器
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T08:28Z` / 2026-09-16 16:28 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `48b0890` 再加 docker.sock / bind-mount 扫描：

- Publish Guard 现禁止 Compose/CI 挂 `docker.sock`，也禁止 `type: bind` 和相对路径宿主机 bind。数据只走本地 named volume `cdt-data`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T08:39Z` / 2026-09-16 16:39 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `d4f4164` 再加 issue_comment/schedule 触发扫描：

- Publish Guard 现禁止 `issue_comment`、`discussion`、`schedule`/`cron` 和 `watch` 触发。fork 的校验只走 push/PR/手动，不要靠评论或定时任务叫醒发布面
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T08:50Z` / 2026-09-16 16:50 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `efbc27f` 再加 Compose cgroup/userns/runtime 扫描：

- Publish Guard 现禁止 Compose `cgroup: host`、`userns_mode: host`、自定义 `runtime` 和 `group_add`。本地容器不能再借宿主命名空间或 NVIDIA runtime 逃逸
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T08:58Z` / 2026-09-16 16:58 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `de25744` 再加 CI job services / GHA cache 扫描：

- Publish Guard 现禁止 workflow `services:` sidecar，以及 `cache-to` / `cache-from` / `type=gha`。不要在 Actions 里起 redis/postgres，也不要把构建缓存推到 registry
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T09:13Z` / 2026-09-16 17:13 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `444f77b` 再加 Compose json-file 日志驱动扫描：

- Publish Guard 现要求 Compose 日志驱动仍是本地 `json-file`（10m × 3），禁止 syslog/fluentd/awslogs 等远程驱动。不要把容器日志送到云端
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T09:23Z` / 2026-09-16 17:23 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `52a34a4` 再加 GitHub Environment job 扫描：

- Publish Guard 现禁止任何 GitHub Environment job（不只是 `production`）。staging/prod 保护环境会带部署密钥，本 fork 不要接
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T09:40Z` / 2026-09-16 17:40 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `f99b66e` 再加 Compose 本地 build context 扫描：

- Publish Guard 现要求 Compose `context: .`、`dockerfile: Dockerfile`，并禁止 `additional_contexts` 与 build `ssh`。不要从邻仓或 SSH agent 掺进构建上下文
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T09:51Z` / 2026-09-16 17:51 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `e91a3f1` 再加 workflow secrets allowlist 扫描：

- Publish Guard 现只允许 `secrets.ANDROID_KEYSTORE_*` / `ANDROID_KEY_*`。其它 `secrets.*`（含云 AK）不得出现在 workflow YAML
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T11:40Z` / 2026-09-16 19:40 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `547a7bb` 再加 Compose profiles/dns/mac 扫描：

- Publish Guard 现禁止 Compose `profiles`、`dns`/`dns_search`/`dns_opt` 和 `mac_address`。不要用 profile 叠一层发布面，也不要自定义 DNS/MAC
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T11:46Z` / 2026-09-16 19:46 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `e24d16b` 再加 github-script 扫描：

- Publish Guard 现禁止 `actions/github-script`。不要用它拿 `GITHUB_TOKEN` 跑任意 JS 去打 tag / 改仓库
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T11:54Z` / 2026-09-16 19:54 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `e97bbec` 再加 Compose hostname/domainname 扫描：

- Publish Guard 现禁止 Compose `hostname` 和 `domainname`。本地容器不要伪装成别的主机名
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T12:03Z` / 2026-09-16 20:03 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `b6317b6` 再加 gh release CLI / npm publish 扫描：

- Publish Guard 现禁止 `gh release create`、`gh auth login`、`actions/create-release` 和 `npm publish`。GitHub Release 只走已加开关的 draft action
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T12:23Z` / 2026-09-16 20:23 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `dad4a5d` 再加 Compose shm/ulimits/oom 扫描：

- Publish Guard 现禁止 Compose `shm_size`、`ulimits` 和 `oom_kill_disable`。资源上限仍是 `pids_limit 256` / `mem_limit 512m` / `cpus 1.0`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T12:34Z` / 2026-09-16 20:34 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `13dc6cc` 再加 QEMU / docker-container Buildx 扫描：

- Publish Guard 现对所有 workflow 禁止 `setup-qemu-action` 和 `docker-container` Buildx。多架构/特权 builder 不要回来；container verify 仍用 `driver: docker`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T12:56Z` / 2026-09-16 20:56 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `572170f` 再加 Compose pid/ipc sharing 扫描：

- Publish Guard 现禁止 Compose `pid`/`ipc` 的 `host`、`shareable`、`service:`、`container:` 共享。不要把本地容器接到别的 PID/IPC 命名空间
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T13:09Z` / 2026-09-16 21:09 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `243fdd1` 再加 extra GitHub write 权限扫描：

- Publish Guard 现禁止 `deployments`/`statuses`/`checks`/`pages`/`repository-projects: write`。本 fork 不要用这些权限做 GitHub Pages 或部署环境
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T13:35Z` / 2026-09-16 21:35 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `6214a7d` 再加 Compose restart on-failure:3 扫描：

- Publish Guard 现要求 Compose `restart: on-failure:3`，并禁止 `always`。本地 daemon 不要无限拉起重启失败的容器
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T13:40Z` / 2026-09-16 21:40 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `bee5561` 再加 upload-artifact 白名单扫描：

- Publish Guard 现只允许 `android-widget.yml` 和 gated `release.yml` 使用 `actions/upload-artifact`。CI / Publish Guard / Container verify 不要上传构建产物
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T14:08Z` / 2026-09-16 22:08 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `500aed0` 再加 Compose labels/storage_opt 扫描：

- Publish Guard 现禁止 Compose `labels` 和 `storage_opt`。OCI 元数据留在 Dockerfile，不要在本地 daemon 上挂 registry 风格 label 或改存储驱动
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T14:39Z` / 2026-09-16 22:39 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `006cb2b` 再加 download-artifact 白名单扫描：

- Publish Guard 现只允许 gated `release.yml` 使用 `actions/download-artifact`。CI / widget / Publish Guard 不要把 Release 产物拉回来再发布
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T14:43Z` / 2026-09-16 22:43 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `955b6cf` 再加 Compose healthcheck 时序扫描：

- Publish Guard 现要求 Compose healthcheck 仍是 30s/5s/10s/3，并禁止 `disable: true`。不要把本地健康检查拉长或关掉
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T15:53Z` / 2026-09-16 23:53 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `c591aad` 再加 standalone actions/cache 扫描：

- Publish Guard 现禁止 `actions/cache@` / `actions/cache/save` / `actions/cache/restore`。setup-go `cache: true` 和 setup-node `cache: npm` 仍可用
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T18:13Z` / 2026-09-17 02:13 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `6970b30` 再加 Compose unconfined LSM 扫描：

- Publish Guard 现禁止 Compose `apparmor:unconfined`、`seccomp:unconfined` 和 `label:disable`。`no-new-privileges` 不能靠关掉 LSM 绕过
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T19:40Z` / 2026-09-17 03:40 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `c77d3da` 再加 GitHub Pages 部署 action 扫描：

- Publish Guard 现禁止 `actions/deploy-pages`、`configure-pages`、`upload-pages-artifact` 和 `peaceiris/actions-gh-pages`。本 fork 不要做 GitHub Pages 发布
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T21:23Z` / 2026-09-17 05:23 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `4417395` 再加 Compose 单 tmpfs 扫描：

- Publish Guard 现只允许 `/tmp` tmpfs（16m, noexec,nosuid,nodev）。不要再挂 `/run` 或其他可写 tmpfs
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T21:30Z` / 2026-09-17 05:30 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `af68421` 再加 Buildx 白名单扫描：

- Publish Guard 现只允许 `.github/workflows/docker-build-push.yml` 使用 `docker/setup-buildx-action` 和 `docker/build-push-action`。CI / widget / Publish Guard 不要起 Buildx
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T21:36Z` / 2026-09-17 05:36 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `5df0e9f` 再加 Compose 单端口扫描：

- Publish Guard 现只允许一条发布端口 `127.0.0.1:43210:8080`。不要再挂 8081 或其他 loopback 口
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T21:57Z` / 2026-09-17 05:57 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `690bfbd` 再加 action-gh-release 白名单扫描：

- Publish Guard 现只允许 gated `release.yml` 使用 `softprops/action-gh-release`。CI / widget / Publish Guard 不要打 GitHub Release
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T22:13Z` / 2026-09-17 06:13 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `1b30090` 再加 Compose env 白名单扫描：

- Publish Guard 现只允许 Compose environment `CDT_DATA_DIR` / `CDT_LISTEN` / `CDT_WORKERS` / `TZ`。不要再加调试或密钥变量
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T22:20Z` / 2026-09-17 06:20 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `9e5ab80` 再加 Android/Gradle action 白名单扫描：

- Publish Guard 现只允许 `android-widget.yml` 使用 `setup-java` / `setup-android` / `setup-gradle` / wrapper-validation。其它 workflow 不要起 Android 构建面
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T22:28Z` / 2026-09-17 06:28 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `d1de3c2` 再加 Compose security_opt 白名单扫描：

- Publish Guard 现只允许 `security_opt: no-new-privileges:true`。不要再加 systempaths/unconfined 等项
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T22:36Z` / 2026-09-17 06:36 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `f483b13` 再加 setup-go/setup-node 白名单扫描：

- Publish Guard 现只允许 `ci.yml` 和 gated `release.yml` 使用 `actions/setup-go` / `setup-node`。Publish Guard / widget / container 不要起 Go/Node 工具链
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T22:50Z` / 2026-09-17 06:50 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `8bb9a5a` 再加 Compose logging 白名单扫描：

- Publish Guard 现只允许 Compose logging `driver: json-file` 和 options `max-size`/`max-file`。不要加 syslog-address 或其它远程日志字段
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T22:54Z` / 2026-09-17 06:54 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `90420ad` 再加 SSH deploy action 扫描：

- Publish Guard 现禁止 `webfactory/ssh-agent`、`appleboy/scp-action` / `ssh-action` 和 `ssh-key:`。本 fork 不要用 SSH 把产物拷到生产机
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T23:05Z` / 2026-09-17 07:05 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `3f07d77` 再加 Compose 单 volume 扫描：

- Publish Guard 现只允许服务 volume `cdt-data:/data`。不要再挂 cache 或其它路径
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T23:15Z` / 2026-09-17 07:15 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `be4fd5b` 再加 checkout token 扫描：

- Publish Guard 现禁止 `actions/checkout` 的 `token:` 覆盖。不要把 PAT 交给 checkout
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T23:33Z` / 2026-09-17 07:33 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `47c116c` 再加 Compose build 白名单扫描：

- Publish Guard 现只允许 Compose `build` 的 `context` / `dockerfile` / `args`，且 args 只有 VERSION/COMMIT/BUILT_AT/IMAGE_SOURCE。不要加 cache_from、secrets 或额外 ARG
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T23:39Z` / 2026-09-17 07:39 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `b088338` 再加 checkout submodules 扫描：

- Publish Guard 现禁止 `actions/checkout` 的 `submodules:`（含 gated auto-release）。不要拉嵌套仓库
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T23:45Z` / 2026-09-17 07:45 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `ca2e905` 再加 Compose cap_drop 白名单扫描：

- Publish Guard 现只允许 Compose `cap_drop: ALL`。不要再列其它 capability
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T23:49Z` / 2026-09-17 07:49 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `531e886` 再加 checkout LFS 扫描：

- Publish Guard 现禁止 `actions/checkout` 的 `lfs:`（含 gated auto-release）。不要拉 Git LFS 对象
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-16T23:59Z` / 2026-09-17 07:59 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `1243a31` 再加 Compose GPU/cgroup 扫描：

- Publish Guard 现禁止 Compose `gpus:` 和 `device_cgroup_rules:`。不要把宿主机 GPU 或设备 cgroup 传进容器
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-17T00:01Z` / 2026-09-17 08:01 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `255e0ea` 再加 checkout sparse-checkout 扫描：

- Publish Guard 现禁止 `actions/checkout` 的 `sparse-checkout` / `sparse-checkout-cone-mode`（含 gated auto-release）。保持 `fetch-depth: 1` 全量工作树
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-17T00:05Z` / 2026-09-17 08:05 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `1c21bbf` 再加 Compose healthcheck 白名单扫描：

- Publish Guard 现只允许 Compose healthcheck `test` / `interval` / `timeout` / `retries` / `start_period`。不要加 `start_interval` 或关掉检查
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-17T00:07Z` / 2026-09-17 08:07 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `252357f` 再加 checkout repository 扫描：

- Publish Guard 现禁止 `actions/checkout` 的 `repository:` 覆盖（含 gated auto-release）。只克隆本 fork
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-17T00:22Z` / 2026-09-17 08:22 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `f089d11` 再加 Compose deploy/cgroup_parent 扫描：

- Publish Guard 现禁止 Compose `deploy:` 和 `cgroup_parent:`。不要用 Swarm 发布面或挂到宿主机 cgroup
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-17T00:29Z` / 2026-09-17 08:29 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `3991778` 再加 checkout github-server-url 扫描：

- Publish Guard 现禁止 `actions/checkout` 的 `github-server-url:`（含 gated auto-release）。只从 github.com 克隆。`path:` 仍不扫，避免误伤 artifact `path:`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-17T00:46Z` / 2026-09-17 08:46 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `e70dd0a` 再加 Compose secrets/configs 扫描：

- Publish Guard 现禁止 Compose `secrets:` 和 `configs:`。不要往容器里挂密钥文件或 config 文件
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-20T11:26Z` / 2026-09-20 19:26 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `7ecbf74` 再加 checkout SSH 扫描：

- Publish Guard 现禁止 `actions/checkout` 的 `ssh-user:` / `ssh-known-hosts:`（含 gated auto-release）。`ssh-key:` 本来就禁止。不要用 SSH 克隆
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-20T11:31Z` / 2026-09-20 19:31 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `a54377d` 再加 Compose credential_spec/isolation 扫描：

- Publish Guard 现禁止 Compose `credential_spec:` 和 `isolation:`。不要换容器隔离面或注入 Windows 凭据规格
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-20T11:42Z` / 2026-09-20 19:42 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `5dddbd1` 再加 checkout ssh-strict 扫描：

- Publish Guard 现禁止 `actions/checkout` 的 `ssh-strict:`（含 gated auto-release）。SSH 克隆面保持关掉
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-20T11:50Z` / 2026-09-20 19:50 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `0059610` 再加 Compose working_dir/platform 扫描：

- Publish Guard 现禁止 Compose `working_dir:` 和 `platform:`。不要改镜像 WORKDIR 或强制另一架构
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-20T12:02Z` / 2026-09-20 20:02 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `0fc8cb2` 再加 Compose scale/links 扫描：

- Publish Guard 现禁止 Compose `scale:` 和 `links` / `external_links`。不要扩副本或加遗留网络链接
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-20T12:05Z` / 2026-09-20 20:05 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `a881aba` 再加 checkout clean 扫描：

- Publish Guard 现禁止 `actions/checkout` 的 `clean:`（含 gated auto-release）。保持默认干净工作区，不要 `clean: false`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-20T12:20Z` / 2026-09-20 20:20 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `7b59c32` 再加 Compose 顶层 volume 白名单扫描：

- Publish Guard 现只允许顶层 named volume `cdt-data`，且不能加 driver/options。不要再声明 cache 或其它卷
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-20T12:27Z` / 2026-09-20 20:27 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `d5c7d8d` 再加 checkout filter 扫描：

- Publish Guard 现禁止 `actions/checkout` 的 `filter:`（含 gated auto-release）。不要用 partial clone 藏文件。`path:` 仍不扫
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-20T12:38Z` / 2026-09-20 20:38 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `d282479` 再加 Compose annotations/cpu_shares 扫描：

- Publish Guard 现禁止 Compose `annotations:` 和 `cpu_shares:`。不要加额外 OCI 注解或抬高 CPU shares
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-20T12:45Z` / 2026-09-20 20:45 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `73f86bf` 再加 checkout set-safe-directory 扫描：

- Publish Guard 现禁止 `actions/checkout` 的 `set-safe-directory:`（含 gated auto-release）。保持 action 默认，不要覆盖 git safe.directory
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-20T12:53Z` / 2026-09-20 20:53 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `a1eac9c` 再加 Compose cpu_quota/cpuset 扫描：

- Publish Guard 现禁止 Compose `cpu_quota` / `cpu_period` 和 `cpuset`。CPU 上限仍只靠 `cpus: 1.0`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-20T12:59Z` / 2026-09-20 20:59 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `7547fef` 再加 checkout fetch-tags 扫描：

- Publish Guard 现禁止 `actions/checkout` 的 `fetch-tags:`（含 gated auto-release）。保持 `fetch-depth: 1`，不要额外拉 tag。`path:` 仍不扫
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-20T13:09Z` / 2026-09-20 21:09 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `24e286a` 再加 Compose blkio/oom_score 扫描：

- Publish Guard 现禁止 Compose `blkio_config:` 和 `oom_score_adj:`。不要改块设备权重或让容器更难被 OOM killer 杀掉
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-20T13:19Z` / 2026-09-20 21:19 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `98b1c87` 再加 checkout show-progress 扫描：

- Publish Guard 现禁止 `actions/checkout` 的 `show-progress:`（含 gated auto-release）。保持 action 默认。`path:` 仍不扫
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-20T13:23Z` / 2026-09-20 21:23 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `c6019b1` 再加 Compose mem_reservation 扫描：

- Publish Guard 现禁止 Compose `mem_reservation` / `memory_reservation`。内存上限仍只靠 `mem_limit: 512m`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-20T13:31Z` / 2026-09-20 21:31 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `2ad84d3` 再加 checkout log-level 扫描：

- Publish Guard 现禁止 `actions/checkout` 的 `log-level:`（含 gated auto-release）。保持 action 默认。`path:` 仍不扫
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`

续推证据（`2026-09-20T13:34Z` / 2026-09-20 21:34 Asia/Taipei），对象 `86669666/CDT-Monitor`，当时 HEAD `6dea325` 再加 Compose mem_swappiness 扫描：

- Publish Guard 现禁止 Compose `mem_swappiness` / `memory_swappiness`。交换仍只靠 `memswap_limit: 512m`
- 这仍不是已经发布，也不是 PR#2 可以合进未加开关 `main`
