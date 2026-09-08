# 本 fork 的本地 Docker

这份说明只覆盖 `86669666/CDT-Monitor` 的本地构建与运行。它不发布镜像，也不替换上游已发布的 `ghcr.io/wang4386/cdt-monitor` / `qninq/cdt-monitor` 安装路径。

本地标签：

```text
ghcr.io/86669666/cdt-monitor:local
```

该名字只是为了标明 fork 来源。仓库内 `docker-compose.yml` 使用 `pull_policy: build`，因此 Compose 只会在本机构建，不会从 GHCR 拉取这个标签，也不要把这个标签 `docker push` / `docker compose push` 出去。

## 镜像形态（现状）

`Dockerfile` 是多阶段构建，当前不要改 Go / 前端业务代码来迁就本地运行：

1. `node:22-alpine`（digest 钉死）构建 `web/`，产物落到 `internal/web/dist`。
2. `golang:1.24-alpine`（digest 钉死）按 `TARGETOS` / `TARGETARCH` 交叉编译 `./cmd/cdt-monitor`（`CGO_ENABLED=0`）。
3. `alpine:3.21`（digest 钉死）只提供 CA 证书。
4. 最终 `scratch` 镜像：非 root `65532:65532`、`VOLUME /data`、`EXPOSE 8080`、入口 `/cdt-monitor serve`、`STOPSIGNAL SIGTERM`，以及镜像内 `HEALTHCHECK`（`/cdt-monitor healthcheck` → `/healthz`）。Compose 另加 `restart: on-failure:3`（本地不自动 unless-stopped）、`no-new-privileges`、`cap_drop: ALL`、`pids_limit: 256`、`mem_limit: 512m`、`stop_grace_period: 15s`，以及 json-file 日志上限 `10m` × 3。

运行镜像里没有 shell、包管理器或阿里云凭据。AccessKey、通知密钥和管理员密码都在首次 Web 向导写入数据卷，不要放进 Compose 或镜像构建参数。

默认 `org.opencontainers.image.source` 仍是上游 `wang4386/CDT-Monitor`（`docker build` 不传参时）。本仓库 Compose 会传入 `IMAGE_SOURCE=https://github.com/86669666/CDT-Monitor`，只影响本地标签 `ghcr.io/86669666/cdt-monitor:local` 的镜像 LABEL，不会 push。镜像 LABEL 另声明 `org.opencontainers.image.licenses=MIT`，与仓库 LICENSE 一致。

## 启动

在仓库根目录：

```bash
docker compose config
docker compose build
docker compose up -d
docker compose logs -f cdt-monitor
```

浏览器访问 `http://127.0.0.1:43210`。第一次进入安装向导。数据在 named volume `cdt-data`。

等价的显式 build：

```bash
docker build   --build-arg VERSION=local   --build-arg COMMIT="$(git rev-parse --short HEAD)"   --build-arg BUILT_AT=local   -t ghcr.io/86669666/cdt-monitor:local   .
```

不要加 `--push`。不要登录 GHCR / Docker Hub 来完成本地验证。

时区：Compose 默认 `TZ=Asia/Taipei`，只影响容器系统时区。业务时区仍以控制台设置为准。需要上海时区时：

```bash
TZ=Asia/Shanghai docker compose up -d
```

或在 overlay / 环境里覆盖 `TZ`。不要把真实 Aliyun AK、SMTP 密码或 Telegram token 写进 Compose。

## 本机验证范围

- 已验证：`docker compose config` 解析为本地 build + `ghcr.io/86669666/cdt-monitor:local`。
- 已验证：`docker compose build --dry-run`。
- 已验证（`2026-09-07T22:42Z` / 2026-09-08 06:42 Asia/Taipei）：`docker compose build` 在本机打出 `ghcr.io/86669666/cdt-monitor:local`（`sha256:ef9fbb591a54…`，约 13.2MB，`USER 65532:65532`，fork `IMAGE_SOURCE`，镜像 HEALTHCHECK 存在）。`docker run --rm --network none … version` 输出 `cdt-monitor local (unknown, local, linux/amd64)`。
- **没有** `docker push` / `docker compose push` / GHCR login。不要把这次本机构建写成已经发布。
- 已验证（`2026-09-07T23:02Z` / 2026-09-08 07:02 Asia/Taipei）：`docker compose up -d --no-build` 后容器 `healthy`，`curl http://127.0.0.1:43210/healthz` 返回 `200 {"status":"ok"}`，进程用户 `65532:65532`，`CapDrop=ALL`，`no-new-privileges`。随后 `docker compose down` 并删除 named volume，避免把本机 `master.key` 留在宿主机。
- 这只证明本地镜像能提供 `/healthz`，不是安装向导、阿里云账号或 GHCR 发布。未做远端 CI。

## 和上游安装文档的关系

[README.MD](../README.MD) 里的 Docker 安装示例仍展示上游已发布镜像，方便对照。本 fork 的默认 Compose 文件已经改为本地构建。若只想跑上游镜像，请显式使用 README 中的 `image:` 片段，而不是这份仓库 Compose。

CI 工作流的镜像名与发布开关见 [CI 发布与密钥审计](ci-publish-audit.md)。
