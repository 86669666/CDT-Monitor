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

## 镜像名

变更前：

- GHCR：`ghcr.io/${{ github.repository_owner }}/cdt-monitor`（在本 fork 会变成 `ghcr.io/86669666/cdt-monitor`）
- Docker Hub：硬编码 `qninq/cdt-monitor`（上游命名空间，不适合 fork）

变更后：

- GHCR 名称仍随 `repository_owner`，但只有仓库变量 `ENABLE_PRODUCTION_PUBLISH=true` 才会 login / push
- `qninq/cdt-monitor` 仅当 `ENABLE_DOCKERHUB_PUBLISH=true` 时写入 metadata
- 本 fork 两个变量都保持未设置

本地开发标签 `ghcr.io/86669666/cdt-monitor:local` 只存在于 [本地 Docker](local-docker.md) 与 `docker-compose.yml`，不会被这个 workflow 推送。

## 触发面

| Workflow | 原行为 | 本 fork |
| --- | --- | --- |
| `CI` | `dev`/`main`/PR | 增加 `work/**`，给隔离工作流分支做 verify |
| `Automatic Release` | `main` push 自动打 tag 并发布 | 需要 `ENABLE_PRODUCTION_PUBLISH=true` |
| `Release Binaries` | tag / 手动 / 被自动发布调用 | 同上变量，否则整条 job 跳过 |
| `Container Images` | `dev`/tag 构建后 `push: true` | 仍可做本机 load 校验；push 需要上述变量 |
| `Android Widget` | 仅 `workflow_dispatch` | 保持手动；产物是 artifact 不是 registry |

不要把一次绿色 CI 或一次本地 Docker 构建写成已经发布 GHCR / Docker Hub。

## 操作红线

- 不要在 `86669666/CDT-Monitor` 上设置 `ENABLE_PRODUCTION_PUBLISH` 或 `ENABLE_DOCKERHUB_PUBLISH`，除非有单独的发布授权。
- 不要配置 `DOCKER_USERNAME` / `DOCKER_PASSWORD` 去推 `qninq/cdt-monitor`。
- 不要 force-push，不要用本分支做 production deploy。
