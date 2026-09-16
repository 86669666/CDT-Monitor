#!/usr/bin/env bash
# Local + CI tripwire for 86669666/CDT-Monitor.
# Fail if fork workflows regain GHCR/Hub publish surfaces, if
# ENABLE_PRODUCTION_PUBLISH / ENABLE_DOCKERHUB_PUBLISH are set true,
# or if Compose drops the loopback bind / grows secret env keys,
# or if the Dockerfile defaults IMAGE_SOURCE back to upstream.
# This script does not publish, log in, or set those variables.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

fail=0
note() { printf '%s\n' "$*"; }
bad() { printf 'FAIL: %s\n' "$*"; fail=1; }

strip_comments() {
  # Drop full-line comments and trailing comments so documented
  # "do not add ghcr.io" notes do not trip the scanner.
  sed -E '/^[[:space:]]*#/d; s/[[:space:]]+#.*$//; /^[[:space:]]*$/d' "$1"
}

require_file() {
  local f="$1"
  if [ ! -f "$f" ]; then
    bad "missing $f"
    return 1
  fi
}

scan_workflows() {
  local f body extra
  shopt -s nullglob
  local files=(.github/workflows/*.yml)
  if [ "${#files[@]}" -eq 0 ]; then
    bad "no workflow files under .github/workflows"
    return
  fi
  for f in "${files[@]}"; do
    body="$(strip_comments "$f")"
    if grep -Eq 'packages:[[:space:]]*write' <<<"$body"; then
      bad "$f: packages: write is forbidden on this fork"
    fi
    if grep -Eq 'docker/login-action' <<<"$body"; then
      bad "$f: docker/login-action is forbidden on this fork"
    fi
    if grep -Eq 'docker/metadata-action' <<<"$body"; then
      bad "$f: docker/metadata-action would reintroduce GHCR/Hub image names"
    fi
    if grep -Eq 'secrets:[[:space:]]*inherit' <<<"$body"; then
      bad "$f: secrets: inherit is forbidden on this fork"
    fi
    if grep -Eq 'ghcr\.io' <<<"$body"; then
      bad "$f: ghcr.io must not appear in workflow YAML (comments excluded)"
    fi
    if grep -Eq 'qninq/cdt-monitor' <<<"$body"; then
      bad "$f: qninq/cdt-monitor is an upstream Hub name; do not restore it"
    fi
    if grep -Eq 'DOCKER_USERNAME|DOCKER_PASSWORD' <<<"$body"; then
      bad "$f: Docker Hub secrets must not be referenced"
    fi
    if grep -Eq 'push:[[:space:]]*true' <<<"$body"; then
      bad "$f: push: true is forbidden on this fork"
    fi
    if grep -Eq 'docker[[:space:]]+push|docker[[:space:]]+compose[[:space:]]+push|[[:space:]]compose[[:space:]]+push' <<<"$body"; then
      bad "$f: docker push / compose push is forbidden on this fork"
    fi
    if grep -Eq '^[[:space:]]+environment:' <<<"$body"; then
      bad "$f: GitHub Environment jobs are forbidden on this fork"
    fi
    if grep -Eq 'curl.*\|[[:space:]]*(ba)?sh|wget.*\|[[:space:]]*(ba)?sh' <<<"$body"; then
      bad "$f: pipe-to-shell installers are forbidden"
    fi
    if grep -Fq 'pull_request_target' <<<"$body"; then
      bad "$f: pull_request_target is forbidden (base-repo privileges on fork PRs)"
    fi
    if grep -Fq 'workflow_run' <<<"$body"; then
      bad "$f: workflow_run triggers are forbidden on this fork"
    fi
    if grep -Fq 'repository_dispatch' <<<"$body"; then
      bad "$f: repository_dispatch is forbidden on this fork"
    fi
    if grep -Eq 'permissions:[[:space:]]*write-all' <<<"$body"; then
      bad "$f: permissions: write-all is forbidden on this fork"
    fi
    if grep -Eq 'continue-on-error:[[:space:]]*true' <<<"$body"; then
      bad "$f: continue-on-error: true is forbidden; do not mask publish/verify failures"
    fi
    if grep -Eiq 'tojson[[:space:]]*\([[:space:]]*secrets[[:space:]]*\)' <<<"$body"; then
      bad "$f: toJSON(secrets) is forbidden; do not dump the secret map into logs"
    fi
    if grep -Fq 'docker.sock' <<<"$body"; then
      bad "$f: docker.sock is forbidden; CI must not control the host Docker daemon"
    fi
    if grep -Fq 'issue_comment' <<<"$body"; then
      bad "$f: issue_comment triggers are forbidden on this fork"
    fi
    if grep -Fq 'discussion' <<<"$body"; then
      bad "$f: discussion triggers are forbidden on this fork"
    fi
    if grep -Eq '^[[:space:]]+schedule:' <<<"$body"; then
      bad "$f: schedule/cron triggers are forbidden on this fork"
    fi
    if grep -Eq '^[[:space:]]+watch:' <<<"$body"; then
      bad "$f: watch triggers are forbidden on this fork"
    fi
    if grep -Eq '^[[:space:]]+services:' <<<"$body"; then
      bad "$f: job services: sidecars are forbidden on this fork"
    fi
    if grep -Eq 'cache-to:|cache-from:|type=gha' <<<"$body"; then
      bad "$f: GHA/registry build cache is forbidden on this fork"
    fi
    extra="$(grep -Eo 'secrets\.[A-Za-z0-9_]+' <<<"$body" | grep -Ev '^secrets\.(ANDROID_KEYSTORE_BASE64|ANDROID_KEYSTORE_PASSWORD|ANDROID_KEY_ALIAS|ANDROID_KEY_PASSWORD)$' || true)"
    if [ -n "$extra" ]; then
      bad "$f: unexpected secret reference: $extra"
    fi
    if grep -Fq 'actions/github-script' <<<"$body"; then
      bad "$f: actions/github-script is forbidden on this fork"
    fi
    if grep -Eq 'gh[[:space:]]+release[[:space:]]+create|gh[[:space:]]+auth[[:space:]]+login' <<<"$body"; then
      bad "$f: gh release/auth CLI is forbidden; keep the gated draft action"
    fi
    if grep -Fq 'actions/create-release' <<<"$body"; then
      bad "$f: actions/create-release is forbidden; keep the gated draft action"
    fi
    if grep -Eq 'npm[[:space:]]+publish' <<<"$body"; then
      bad "$f: npm publish is forbidden on this fork"
    fi
    if grep -Fq 'setup-qemu-action' <<<"$body"; then
      bad "$f: QEMU/setup-qemu-action is forbidden on this fork"
    fi
    if grep -Fq 'docker-container' <<<"$body"; then
      bad "$f: privileged docker-container Buildx is forbidden; keep driver: docker"
    fi
  done
}

scan_auto_release() {
  local f=".github/workflows/auto-release.yml"
  require_file "$f" || return
  local body
  body="$(strip_comments "$f")"
  if grep -Eq '^[[:space:]]*push:' <<<"$body"; then
    bad "$f: on.push is forbidden; keep workflow_dispatch only"
  fi
  local gates
  gates="$(grep -c 'vars.ENABLE_PRODUCTION_PUBLISH == '\''true'\''' "$f" || true)"
  if [ "$gates" -lt 3 ]; then
    bad "$f: tag, release, and container jobs must each gate on ENABLE_PRODUCTION_PUBLISH (found $gates)"
  fi
  if ! grep -Fq 'name: Create tag (gated)' "$f"; then
    bad "$f: tag job must stay named Create tag (gated)"
  fi
  if ! grep -Fq 'v[0-9]+\.[0-9]+\.[0-9]+$' "$f"; then
    bad "$f: tag job must keep the vMAJOR.MINOR.PATCH version regex"
  fi
  if ! grep -Fq 'github-actions[bot]' "$f"; then
    bad "$f: tagger must stay github-actions[bot]"
  fi
}

scan_release_binaries() {
  local f=".github/workflows/release.yml"
  require_file "$f" || return
  local body
  body="$(strip_comments "$f")"
  if ! grep -Eq 'draft:[[:space:]]*true' <<<"$body"; then
    bad "$f: GitHub Release must stay draft: true"
  fi
  if grep -Eq 'draft:[[:space:]]*false' <<<"$body"; then
    bad "$f: draft: false is forbidden on this fork"
  fi
  if ! grep -Eq 'make_latest:[[:space:]]*false' <<<"$body"; then
    bad "$f: make_latest must stay false"
  fi
  if grep -Eq 'make_latest:[[:space:]]*true' <<<"$body"; then
    bad "$f: make_latest: true is forbidden on this fork"
  fi
  if ! grep -Eq 'generate_release_notes:[[:space:]]*false' <<<"$body"; then
    bad "$f: generate_release_notes must stay false"
  fi
  if ! grep -Fq 'name: Draft GitHub Release (gated, not latest)' "$f"; then
    bad "$f: publish job must stay named Draft GitHub Release (gated, not latest)"
  fi
  if ! grep -Eq '\{ goos: linux, goarch: amd64 \}' <<<"$body"; then
    bad "$f: release matrix must keep linux/amd64"
  fi
  local os_count
  os_count="$(grep -c 'goos:' <<<"$body" || true)"
  if [ "$os_count" -ne 1 ]; then
    bad "$f: this fork must not restore a multi-OS release matrix (goos count=$os_count)"
  fi
  if grep -Eq 'goos:[[:space:]]*(windows|darwin)|goarch:[[:space:]]*arm|goarm:' <<<"$body"; then
    bad "$f: windows/darwin/arm release targets are forbidden on this fork"
  fi
}

scan_container() {
  local f=".github/workflows/docker-build-push.yml"
  require_file "$f" || return
  local body
  body="$(strip_comments "$f")"
  if ! grep -Eq 'push:[[:space:]]*false' <<<"$body"; then
    bad "$f: container verify must keep push: false"
  fi
  if ! grep -Eq 'cdt-monitor:verify-amd64' <<<"$body"; then
    bad "$f: container verify must keep the local tag cdt-monitor:verify-amd64"
  fi
  if grep -Eq '^  push:' <<<"$body"; then
    bad "$f: do not restore on.push (dev/tag); keep workflow_dispatch / workflow_call"
  fi
  if grep -Eq "tags:[[:space:]]*\['v" <<<"$body"; then
    bad "$f: do not restore v-tag push triggers"
  fi
  if ! grep -Fq 'name: Load-verify linux/amd64 (no push)' "$f"; then
    bad "$f: job must stay named Load-verify linux/amd64 (no push)"
  fi
  if ! grep -Eq 'driver:[[:space:]]*docker$' <<<"$body"; then
    bad "$f: Buildx must keep driver: docker"
  fi
  if grep -Eq 'setup-qemu-action' <<<"$body"; then
    bad "$f: QEMU is forbidden on this fork"
  fi
  if ! grep -Eq 'load:[[:space:]]*true' <<<"$body"; then
    bad "$f: container verify must keep load: true"
  fi
  if ! grep -Eq 'provenance:[[:space:]]*false' <<<"$body"; then
    bad "$f: provenance must stay false"
  fi
  if ! grep -Eq 'sbom:[[:space:]]*false' <<<"$body"; then
    bad "$f: sbom must stay false"
  fi
  if ! grep -Eq 'platforms:[[:space:]]*linux/amd64' <<<"$body"; then
    bad "$f: platforms must stay linux/amd64"
  fi
  if ! grep -Eq -- '--network none' <<<"$body"; then
    bad "$f: version check must use --network none"
  fi
  if ! grep -Eq -- '--read-only' <<<"$body"; then
    bad "$f: version check must use --read-only"
  fi
  if ! grep -Eq -- '--user 65532:65532' <<<"$body"; then
    bad "$f: version check must run as 65532:65532"
  fi
  if grep -Eq 'type=gha|cache-to:' <<<"$body"; then
    bad "$f: GHA/registry cache-to is forbidden on this fork"
  fi
}

scan_widget() {
  local f=".github/workflows/android-widget.yml"
  require_file "$f" || return
  local body
  body="$(strip_comments "$f")"
  if grep -Eq '^  push:' <<<"$body"; then
    bad "$f: widget CI must stay workflow_dispatch only"
  fi
  if ! grep -Fq 'name: Build widget packages (artifact only)' "$f"; then
    bad "$f: job must stay named Build widget packages (artifact only)"
  fi
  if ! grep -Eq "java-version:[[:space:]]*'17'" <<<"$body"; then
    bad "$f: widget CI must stay on JDK 17"
  fi
  if ! grep -Eq 'timeout-minutes:[[:space:]]*20' <<<"$body"; then
    bad "$f: widget CI must keep timeout-minutes: 20"
  fi
  if grep -Eiq 'gradle-play-publisher|upload-google-play|play-console' <<<"$body"; then
    bad "$f: Play Store upload is forbidden on this fork"
  fi
  if ! grep -Fq 'if: always()' "$f"; then
    bad "$f: keystore cleanup must run if: always()"
  fi
  if ! grep -Eq 'shred' <<<"$body"; then
    bad "$f: decoded keystore must be shredded"
  fi
  if ! grep -Eq 'umask 077' <<<"$body"; then
    bad "$f: keystore decode must umask 077"
  fi
  if ! grep -Eq 'RUNNER_TEMP' <<<"$body"; then
    bad "$f: decoded keystore must stay in RUNNER_TEMP"
  fi
  if ! grep -Fq 'secrets.ANDROID_KEYSTORE_BASE64' "$f"; then
    bad "$f: keystore must come from secrets.ANDROID_KEYSTORE_BASE64"
  fi
  if grep -Eq 'BEGIN (RSA |PRIVATE|CERTIFICATE)|keystorepassword:' <<<"$body"; then
    bad "$f: do not embed keystore material in YAML"
  fi
  if ! grep -Eq 'gradle/actions/wrapper-validation@' <<<"$body"; then
    bad "$f: Gradle Wrapper validation is required"
  fi
  if ! grep -Eq 'gradle/actions/setup-gradle@' <<<"$body"; then
    bad "$f: setup-gradle is required"
  fi
  local wrap setup
  wrap="$(grep -E 'gradle/actions/wrapper-validation@' <<<"$body" | head -1 || true)"
  setup="$(grep -E 'gradle/actions/setup-gradle@' <<<"$body" | head -1 || true)"
  wrap="${wrap##*@}"
  setup="${setup##*@}"
  if [ -n "$wrap" ] && [ -n "$setup" ] && [ "$wrap" != "$setup" ]; then
    bad "$f: wrapper-validation and setup-gradle must share the same action SHA"
  fi
  if ! grep -Eq 'assembleDebug assembleRelease bundleRelease' <<<"$body"; then
    bad "$f: widget CI must keep assembleDebug assembleRelease bundleRelease"
  fi
  if ! grep -Eq -- '--no-daemon' <<<"$body"; then
    bad "$f: Gradle must run --no-daemon"
  fi
  if ! grep -Eq 'sdkmanager --licenses' <<<"$body"; then
    bad "$f: SDK licenses must be accepted non-interactively"
  fi
  if ! grep -Fq 'platforms;android-35' "$f"; then
    bad "$f: widget CI must install platforms;android-35"
  fi
  if ! grep -Eq 'distribution:[[:space:]]*temurin' <<<"$body"; then
    bad "$f: setup-java must stay temurin"
  fi
  if ! grep -Eq 'gradle-home-cache-cleanup:[[:space:]]*true' <<<"$body"; then
    bad "$f: setup-gradle must keep gradle-home-cache-cleanup: true"
  fi
  if ! grep -Fq 'android-widget/app/build/outputs/apk/debug/*.apk' "$f"; then
    bad "$f: artifact paths must include debug APK"
  fi
  if ! grep -Fq 'android-widget/app/build/outputs/apk/release/*.apk' "$f"; then
    bad "$f: artifact paths must include release APK"
  fi
  if ! grep -Fq 'android-widget/app/build/outputs/bundle/release/*.aab' "$f"; then
    bad "$f: artifact paths must include release AAB"
  fi
  if grep -Eq 'app/build/outputs/.*\.jks|app/build/outputs/.*\.keystore' <<<"$body"; then
    bad "$f: keystore files must not be uploaded as artifacts"
  fi
  if ! grep -Eq 'working-directory:[[:space:]]*android-widget' <<<"$body"; then
    bad "$f: Gradle must run with working-directory android-widget"
  fi
  if ! grep -Eq 'android-actions/setup-android@' <<<"$body"; then
    bad "$f: setup-android is required"
  fi
}

scan_checkout_credentials() {
  local f body base
  shopt -s nullglob
  for f in .github/workflows/*.yml; do
    body="$(strip_comments "$f")"
    base="$(basename "$f")"
    if [ "$base" = "auto-release.yml" ]; then
      if ! grep -Eq 'persist-credentials:[[:space:]]*true' <<<"$body"; then
        bad "$f: gated tag job must keep persist-credentials true for git push tag"
      fi
      continue
    fi
    if grep -Eq 'persist-credentials:[[:space:]]*true' <<<"$body"; then
      bad "$f: persist-credentials: true is forbidden outside Automatic Release tag"
    fi
    if grep -q 'actions/checkout@' <<<"$body" && ! grep -Eq 'persist-credentials:[[:space:]]*false' <<<"$body"; then
      bad "$f: checkout must set persist-credentials: false"
    fi
  done
}

scan_job_limits() {
  local f body base runs timeouts
  shopt -s nullglob
  for f in .github/workflows/*.yml; do
    body="$(strip_comments "$f")"
    base="$(basename "$f")"
    if grep -Eq 'id-token:[[:space:]]*write' <<<"$body"; then
      bad "$f: id-token: write is forbidden on this fork"
    fi
    if grep -Eq 'actions:[[:space:]]*write' <<<"$body"; then
      bad "$f: actions: write is forbidden on this fork"
    fi
    if grep -Eq 'pull-requests:[[:space:]]*write' <<<"$body"; then
      bad "$f: pull-requests: write is forbidden on this fork"
    fi
    if grep -Eq 'attestations:[[:space:]]*write' <<<"$body"; then
      bad "$f: attestations: write is forbidden on this fork"
    fi
    if grep -Eq 'security-events:[[:space:]]*write' <<<"$body"; then
      bad "$f: security-events: write is forbidden on this fork"
    fi
    case "$base" in
      auto-release.yml|release.yml) ;;
      *)
        if grep -Eq 'contents:[[:space:]]*write' <<<"$body"; then
          bad "$f: contents: write is forbidden outside gated Automatic Release / Release Binaries"
        fi
        ;;
    esac
    runs="$(grep -c 'runs-on:' <<<"$body" || true)"
    timeouts="$(grep -c 'timeout-minutes:' <<<"$body" || true)"
    if [ "$runs" -gt "$timeouts" ]; then
      bad "$f: each runs-on job must set timeout-minutes (runs-on=$runs timeout-minutes=$timeouts)"
    fi
    if grep -Fq 'self-hosted' <<<"$body"; then
      bad "$f: self-hosted runners are forbidden on this fork"
    fi
    if grep -E '^[[:space:]]*runs-on:' <<<"$body" | grep -Evq '^[[:space:]]*runs-on:[[:space:]]*ubuntu-latest$'; then
      bad "$f: runs-on must stay ubuntu-latest"
    fi
  done
}

scan_action_pins() {
  local f body line ref sha
  shopt -s nullglob
  for f in .github/workflows/*.yml; do
    body="$(strip_comments "$f")"
    if grep -q 'actions/checkout@' <<<"$body" && ! grep -Eq 'fetch-depth:[[:space:]]*1' <<<"$body"; then
      bad "$f: checkout must set fetch-depth: 1"
    fi
    while IFS= read -r line; do
      ref="${line#*uses:}"
      ref="${ref#"${ref%%[![:space:]]*}"}"
      ref="${ref%"${ref##*[![:space:]]}"}"
      case "$ref" in
        ./*) continue ;;
        '') continue ;;
      esac
      sha="${ref##*@}"
      if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ]]; then
        bad "$f: third-party action must be SHA-pinned: $ref"
      fi
    done < <(grep -E 'uses:' <<<"$body" || true)
  done
}

scan_workflow_hygiene() {
  local f body base
  shopt -s nullglob
  for f in .github/workflows/*.yml; do
    body="$(strip_comments "$f")"
    base="$(basename "$f")"
    if ! grep -Eq '^concurrency:' <<<"$body"; then
      bad "$f: missing top-level concurrency group"
    fi
    if ! grep -Eq '^permissions:' <<<"$body"; then
      bad "$f: missing top-level permissions"
    fi
    if ! grep -Eq '^  contents:[[:space:]]*read$' <<<"$body"; then
      bad "$f: workflow-level permissions must be contents: read"
    fi
    if grep -Eq '^  contents:[[:space:]]*write' <<<"$body"; then
      bad "$f: workflow-level contents: write is forbidden; only gated jobs may elevate"
    fi
    if grep -Eq '^  packages:' <<<"$body"; then
      bad "$f: workflow-level packages permission is forbidden on this fork"
    fi
    case "$base" in
      auto-release.yml|release.yml)
        if ! grep -Eq 'cancel-in-progress:[[:space:]]*false' <<<"$body"; then
          bad "$f: gated release workflows must keep cancel-in-progress: false"
        fi
        ;;
      *)
        if ! grep -Eq 'cancel-in-progress:[[:space:]]*true' <<<"$body"; then
          bad "$f: verify workflows must set cancel-in-progress: true"
        fi
        ;;
    esac
    if grep -q 'actions/upload-artifact@' <<<"$body"; then
      if ! grep -Eq 'retention-days:[[:space:]]*7' <<<"$body"; then
        bad "$f: upload-artifact must set retention-days: 7"
      fi
      if grep -Eq 'retention-days:[[:space:]]*([8-9]|[1-9][0-9]+)' <<<"$body"; then
        bad "$f: artifact retention longer than 7 days is forbidden on this fork"
      fi
    fi
  done
}

scan_dockerfile() {
  local f="Dockerfile"
  require_file "$f" || return
  local body
  body="$(strip_comments "$f")"
  if ! grep -Eq 'syntax=docker/dockerfile:.*@sha256:' "$f"; then
    bad "$f: dockerfile frontend must stay digest-pinned (# syntax=docker/dockerfile:...@sha256:...)"
  fi
  if ! grep -Fq 'ARG IMAGE_SOURCE=https://github.com/86669666/CDT-Monitor' <<<"$body"; then
    bad "$f: default IMAGE_SOURCE must stay https://github.com/86669666/CDT-Monitor"
  fi
  if ! grep -Fq 'org.opencontainers.image.source="${IMAGE_SOURCE}"' <<<"$body"; then
    bad "$f: OCI source label must use IMAGE_SOURCE"
  fi
  if ! grep -Fq 'org.opencontainers.image.licenses="MIT"' <<<"$body"; then
    bad "$f: OCI licenses label must stay MIT"
  fi
  if grep -Eq 'wang4386' <<<"$body"; then
    bad "$f: do not default image source to upstream wang4386"
  fi
  if grep -Eq '(^|[[:space:]])--push([[:space:]]|$)' <<<"$body"; then
    bad "$f: --push is forbidden in the Dockerfile"
  fi
  if ! grep -Eq '^USER 65532:65532$' <<<"$body"; then
    bad "$f: final image must stay USER 65532:65532"
  fi
  if grep -Eq '^USER (0|root)(:0)?$' <<<"$body"; then
    bad "$f: USER root/0 is forbidden"
  fi
  if grep -Eq '^ADD ' <<<"$body"; then
    bad "$f: ADD is forbidden; keep COPY"
  fi
  if ! grep -Fq 'VOLUME ["/data"]' <<<"$body"; then
    bad "$f: VOLUME must stay /data"
  fi
  if ! grep -Fq -- '--chown=65532:65532 /runtime-data /data' <<<"$body"; then
    bad "$f: /data must be copied --chown=65532:65532"
  fi
  if ! grep -Fq 'apk add --no-cache ca-certificates' <<<"$body"; then
    bad "$f: certificates stage must install ca-certificates"
  fi
  if grep -Eq 'apt-get |yum |dnf |microdnf ' <<<"$body"; then
    bad "$f: apt/yum/dnf is forbidden; keep alpine apk for CA certs only"
  fi
  local apk
  apk="$(grep -c 'apk add' <<<"$body" || true)"
  if [ "$apk" -ne 1 ]; then
    bad "$f: only one apk add is allowed (ca-certificates), found $apk"
  fi
  if ! grep -Fq '/etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt' <<<"$body"; then
    bad "$f: scratch image must copy ca-certificates.crt"
  fi
  if ! grep -Eq -- 'npm ci --ignore-scripts' <<<"$body"; then
    bad "$f: frontend stage must npm ci --ignore-scripts"
  fi
  if ! grep -Eq 'npm run build' <<<"$body"; then
    bad "$f: frontend stage must npm run build"
  fi
  if ! grep -Eq 'CGO_ENABLED=0' <<<"$body"; then
    bad "$f: Go build must stay CGO_ENABLED=0"
  fi
  if ! grep -Eq '^ARG TARGETOS$' <<<"$body"; then
    bad "$f: TARGETOS must stay an ARG without a default (BuildKit injects it)"
  fi
  if ! grep -Eq '^ARG TARGETARCH$' <<<"$body"; then
    bad "$f: TARGETARCH must stay an ARG without a default (BuildKit injects it)"
  fi
  if grep -Eq '^ARG TARGETOS=' <<<"$body" || grep -Eq '^ARG TARGETARCH=' <<<"$body"; then
    bad "$f: do not default TARGETOS/TARGETARCH; that can ship the wrong GOARCH"
  fi
  if ! grep -Fq 'GOOS=${TARGETOS} GOARCH=${TARGETARCH}' <<<"$body"; then
    bad "$f: go build must use GOOS=\${TARGETOS} GOARCH=\${TARGETARCH}"
  fi
  if ! grep -Fq './cmd/cdt-monitor' "$f"; then
    bad "$f: Go build target must stay ./cmd/cdt-monitor"
  fi
  if ! grep -Fq -- '-o /cdt-monitor' <<<"$body"; then
    bad "$f: go build must write -o /cdt-monitor"
  fi
  if ! grep -Fq -- 'COPY --from=frontend /src/internal/web/dist ./internal/web/dist' <<<"$body"; then
    bad "$f: embedded UI must come from the frontend stage, not a host dist/"
  fi
  if ! grep -Fq -- 'COPY --from=builder /cdt-monitor /cdt-monitor' <<<"$body"; then
    bad "$f: scratch image must copy /cdt-monitor from the builder stage"
  fi
  if ! grep -Fq 'COPY web/package.json web/package-lock.json ./' <<<"$body"; then
    bad "$f: frontend deps must copy package-lock.json before npm ci"
  fi
  if ! grep -Fq 'COPY go.mod go.sum ./' <<<"$body"; then
    bad "$f: Go deps must copy go.mod/go.sum before go mod download"
  fi
  if ! grep -Eq '^COPY web \./$' <<<"$body"; then
    bad "$f: frontend stage must COPY web ./ after the lockfile"
  fi
  if ! grep -Eq '^COPY \. \./$' <<<"$body"; then
    bad "$f: builder must COPY . ./ after go mod download"
  fi
  if ! grep -Fq 'RUN go mod download' <<<"$body"; then
    bad "$f: builder must run go mod download"
  fi
  if ! grep -Fq -- '-trimpath' <<<"$body"; then
    bad "$f: go build must keep -trimpath"
  fi
  if ! grep -Fq -- '-ldflags="-s -w' <<<"$body"; then
    bad "$f: go build must keep -ldflags -s -w"
  fi
  if ! grep -Fq -- '-X main.version=${VERSION}' <<<"$body"; then
    bad "$f: go build must stamp main.version from VERSION"
  fi
  if ! grep -Eq '^ARG VERSION=dev$' <<<"$body"; then
    bad "$f: VERSION must default to dev for local builds"
  fi
  if ! grep -Eq '^ARG COMMIT=unknown$' <<<"$body"; then
    bad "$f: COMMIT must default to unknown for local builds"
  fi
  if ! grep -Eq '^ARG BUILT_AT=unknown$' <<<"$body"; then
    bad "$f: BUILT_AT must default to unknown for local builds"
  fi
  if ! grep -Fq 'mkdir -p /runtime-data' <<<"$body"; then
    bad "$f: builder must mkdir /runtime-data for the empty /data volume"
  fi
  if ! grep -Eq '^WORKDIR /src/web$' <<<"$body"; then
    bad "$f: frontend WORKDIR must stay /src/web"
  fi
  if ! grep -Eq '^WORKDIR /src$' <<<"$body"; then
    bad "$f: builder WORKDIR must stay /src"
  fi
  if ! grep -Eq ' AS frontend$' <<<"$body"; then
    bad "$f: node stage must stay AS frontend"
  fi
  if ! grep -Eq ' AS builder$' <<<"$body"; then
    bad "$f: golang stage must stay AS builder"
  fi
  if ! grep -Eq ' AS certificates$' <<<"$body"; then
    bad "$f: alpine CA stage must stay AS certificates"
  fi
  if ! grep -Eq '^FROM scratch$' <<<"$body"; then
    bad "$f: final stage must stay FROM scratch"
  fi
  if grep -Eq '^FROM --platform=.* scratch' <<<"$body"; then
    bad "$f: final scratch stage must stay unpinned so the image platform matches TARGET"
  fi
  local bp
  bp="$(grep -c -F -- 'FROM --platform=$BUILDPLATFORM' <<<"$body" || true)"
  if [ "$bp" -lt 3 ]; then
    bad "$f: node/go/alpine stages must pin --platform=\$BUILDPLATFORM (found $bp)"
  fi
  if ! grep -Eq '^HEALTHCHECK ' <<<"$body"; then
    bad "$f: HEALTHCHECK is required"
  fi
  if ! grep -Eq 'HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3' <<<"$body"; then
    bad "$f: HEALTHCHECK timing must stay 30s/5s/10s/3"
  fi
  if ! grep -Fq 'CMD ["/cdt-monitor", "healthcheck"]' <<<"$body"; then
    bad "$f: HEALTHCHECK must stay /cdt-monitor healthcheck"
  fi
  if ! grep -Eq '^EXPOSE 8080$' <<<"$body"; then
    bad "$f: EXPOSE must stay 8080"
  fi
  if grep -Eq '^EXPOSE (80|443)$' <<<"$body"; then
    bad "$f: do not EXPOSE 80/443; TLS stays at the reverse proxy"
  fi
  if ! grep -Eq '^STOPSIGNAL SIGTERM$' <<<"$body"; then
    bad "$f: STOPSIGNAL must stay SIGTERM"
  fi
  if ! grep -Eq '^ENTRYPOINT \["/cdt-monitor"\]$' <<<"$body"; then
    bad "$f: ENTRYPOINT must stay /cdt-monitor"
  fi
  if ! grep -Eq '^CMD \["serve"\]$' <<<"$body"; then
    bad "$f: CMD must stay serve"
  fi
  if grep -Eq '(^|[[:space:]])(curl|wget)([[:space:]|;]|$)' <<<"$body"; then
    bad "$f: curl/wget is forbidden; keep apk ca-certificates only"
  fi
  if grep -Eq '^ONBUILD ' <<<"$body"; then
    bad "$f: ONBUILD is forbidden"
  fi
  if grep -Eq '^SHELL ' <<<"$body"; then
    bad "$f: SHELL overrides are forbidden"
  fi
  if grep -Eq 'FROM[[:space:]].*:latest' <<<"$body"; then
    bad "$f: :latest base tags are forbidden"
  fi
  local line
  while IFS= read -r line; do
    case "$line" in
      FROM\ scratch|FROM\ scratch*) continue ;;
    esac
    if [[ "$line" == FROM* && "$line" != *@sha256:* ]]; then
      bad "$f: non-scratch FROM must be digest-pinned: $line"
    fi
  done < <(grep -E '^FROM ' <<<"$body" || true)
}

scan_dependabot() {
  local f=".github/dependabot.yml"
  require_file "$f" || return
  local body targets
  body="$(strip_comments "$f")"
  if grep -Eq 'target-branch:[[:space:]]*main' <<<"$body"; then
    bad "$f: target-branch must not be main while origin/main has ungated auto-release"
  fi
  targets="$(grep -c 'target-branch:[[:space:]]*work/ops' <<<"$body" || true)"
  if [ "$targets" -lt 3 ]; then
    bad "$f: each update ecosystem must target work/ops (found $targets)"
  fi
}

scan_ci_verify() {
  local f=".github/workflows/ci.yml"
  require_file "$f" || return
  local body
  body="$(strip_comments "$f")"
  if ! grep -Fq "name: Verify (no publish)" "$f"; then
    bad "$f: verify job must stay named Verify (no publish)"
  fi
  if ! grep -Eq "go-version:[[:space:]]*'1\.24" <<<"$body"; then
    bad "$f: setup-go must stay on Go 1.24.x"
  fi
  if ! grep -Eq "node-version:[[:space:]]*'22" <<<"$body"; then
    bad "$f: setup-node must stay on Node 22.x"
  fi
  if ! grep -Eq 'go test -race' <<<"$body"; then
    bad "$f: verify must keep go test -race"
  fi
  if ! grep -Eq 'go vet' <<<"$body"; then
    bad "$f: verify must keep go vet"
  fi
  if ! grep -Eq 'CGO_ENABLED=0 GOOS=linux GOARCH=amd64' <<<"$body"; then
    bad "$f: Linux build must stay CGO_ENABLED=0 linux/amd64"
  fi
  if ! grep -Eq 'npm run build' <<<"$body"; then
    bad "$f: verify must keep npm run build"
  fi
  if ! grep -Eq 'working-directory:[[:space:]]*web' <<<"$body"; then
    bad "$f: frontend build must stay in web/"
  fi
  if ! grep -Eq 'cache-dependency-path:[[:space:]]*web/package-lock.json' <<<"$body"; then
    bad "$f: npm cache must use web/package-lock.json"
  fi
  if ! grep -Eq 'go build' <<<"$body"; then
    bad "$f: verify must keep go build"
  fi
  if ! grep -Fq './cmd/cdt-monitor' "$f"; then
    bad "$f: Linux build target must stay ./cmd/cdt-monitor"
  fi
  if ! grep -Eq -- '-trimpath' <<<"$body"; then
    bad "$f: go build must keep -trimpath"
  fi
}

scan_npm_ci() {
  local f body
  shopt -s nullglob
  for f in .github/workflows/*.yml; do
    body="$(strip_comments "$f")"
    if grep -Eq 'npm[[:space:]]+ci' <<<"$body" && ! grep -Eq 'npm[[:space:]]+ci[[:space:]]+--ignore-scripts' <<<"$body"; then
      bad "$f: npm ci must use --ignore-scripts"
    fi
  done
}

scan_dockerignore() {
  local f=".dockerignore"
  require_file "$f" || return
  local required missing
  required=(.github android-widget .env '*.jks' '*.keystore' master.key '*.sqlite' docs)
  for missing in "${required[@]}"; do
    if ! grep -Fxq "$missing" "$f"; then
      bad "$f: missing required exclude $missing"
    fi
  done
}

scan_compose() {
  local f="docker-compose.yml"
  require_file "$f" || return
  local body images svc_keys image_count
  body="$(strip_comments "$f")"
  images="$(grep -E '^[[:space:]]*image:' <<<"$body" || true)"
  if [ -z "$images" ]; then
    bad "$f: missing image:"
    return
  fi
  if grep -Eq 'ghcr\.io|qninq/' <<<"$images"; then
    bad "$f: image: must not use GHCR or qninq Hub names"
  fi
  if grep -Eq '^[[:space:]]*image:[[:space:]].*/' <<<"$images"; then
    bad "$f: image: must stay an unprefixed local tag (no registry slash)"
  fi
  if grep -Eq '0\.0\.0\.0' <<<"$body"; then
    bad "$f: 0.0.0.0 bind is forbidden; keep 127.0.0.1 until CDT_TRUSTED_PROXIES exists"
  fi
  if ! grep -Eq '^[[:space:]]*-[[:space:]]*"127\.0\.0\.1:43210:8080"' <<<"$body"; then
    bad "$f: published port must stay 127.0.0.1:43210:8080"
  fi
  if grep -Eq ':(80|443):|"80:|"443:' <<<"$body"; then
    bad "$f: do not publish host 80/443; TLS stays at the reverse proxy"
  fi
  if grep -Eq '^[[:space:]]*-[[:space:]]*"?[0-9]+:[0-9]+' <<<"$body"; then
    bad "$f: host port without 127.0.0.1 publishes 0.0.0.0"
  fi
  if grep -Eq '^[[:space:]]+(CDT_MASTER_KEY|CDT_TRUSTED_PROXIES|ENABLE_PRODUCTION_PUBLISH|ENABLE_DOCKERHUB_PUBLISH|DOCKER_USERNAME|DOCKER_PASSWORD|ANDROID_KEYSTORE_BASE64|ANDROID_KEYSTORE_PASSWORD|ANDROID_KEY_ALIAS|ANDROID_KEY_PASSWORD):' <<<"$body"; then
    bad "$f: do not put publish vars, cloud secrets, or unimplemented CDT_TRUSTED_PROXIES in Compose"
  fi
  if grep -Eiq '^[[:space:]]+([A-Z0-9_]*ACCESS_KEY[A-Z0-9_]*|[A-Z0-9_]*SECRET[A-Z0-9_]*|SMTP_PASSWORD|TELEGRAM_TOKEN|BOT_TOKEN):' <<<"$body"; then
    bad "$f: do not put Aliyun/notify secrets in Compose env"
  fi
  if ! grep -Eq '^[[:space:]]+pull_policy:[[:space:]]*build$' <<<"$body"; then
    bad "$f: pull_policy must stay build so Compose cannot pull/push a registry tag"
  fi
  if ! grep -Eq '^[[:space:]]+context:[[:space:]]*\.$' <<<"$body"; then
    bad "$f: build context must stay ."
  fi
  if ! grep -Eq '^[[:space:]]+dockerfile:[[:space:]]*Dockerfile$' <<<"$body"; then
    bad "$f: dockerfile must stay Dockerfile"
  fi
  if grep -Eq '^[[:space:]]+additional_contexts:' <<<"$body"; then
    bad "$f: additional_contexts is forbidden; keep a single local context"
  fi
  if grep -Eq '^[[:space:]]+ssh:' <<<"$body"; then
    bad "$f: build ssh mounts are forbidden"
  fi
  if grep -Eq 'privileged:[[:space:]]*true' <<<"$body"; then
    bad "$f: privileged: true is forbidden on this fork"
  fi
  if ! grep -Eq 'privileged:[[:space:]]*false' <<<"$body"; then
    bad "$f: privileged must stay false"
  fi
  if ! grep -Eq 'no-new-privileges:true' <<<"$body"; then
    bad "$f: no-new-privileges:true is required"
  fi
  if ! grep -Eq '^[[:space:]]+-[[:space:]]*ALL$' <<<"$body"; then
    bad "$f: cap_drop must include ALL"
  fi
  if ! grep -Eq 'read_only:[[:space:]]*true' <<<"$body"; then
    bad "$f: read_only must stay true"
  fi
  if ! grep -Eq 'user:[[:space:]]*"65532:65532"' <<<"$body"; then
    bad "$f: container user must stay 65532:65532"
  fi
  if grep -Eq 'unless-stopped' <<<"$body"; then
    bad "$f: unless-stopped is forbidden on this local-only Compose"
  fi
  if ! grep -Eq 'restart:[[:space:]]*on-failure' <<<"$body"; then
    bad "$f: restart must stay on-failure"
  fi
  if ! grep -Eq '/tmp:size=16m,mode=1777,noexec,nosuid,nodev' <<<"$body"; then
    bad "$f: /tmp tmpfs must stay noexec,nosuid,nodev"
  fi
  if ! grep -Fq '/cdt-monitor", "healthcheck"' <<<"$body"; then
    bad "$f: healthcheck must stay /cdt-monitor healthcheck"
  fi
  if ! grep -Eq 'max-size:[[:space:]]*"10m"' <<<"$body"; then
    bad "$f: json-file logs must stay max-size 10m"
  fi
  if ! grep -Eq 'max-file:[[:space:]]*"3"' <<<"$body"; then
    bad "$f: json-file logs must stay max-file 3"
  fi
  if ! grep -Eq 'driver:[[:space:]]*json-file' <<<"$body"; then
    bad "$f: logging driver must stay json-file"
  fi
  if grep -Eq 'driver:[[:space:]]*(syslog|journald|gelf|fluentd|awslogs|splunk|gcplogs|logentries|etwlogs|loki)' <<<"$body"; then
    bad "$f: remote logging drivers are forbidden on this local Compose"
  fi
  if ! grep -Eq 'init:[[:space:]]*true' <<<"$body"; then
    bad "$f: init: true is required so PID 1 can reap"
  fi
  if ! grep -Eq 'pids_limit:[[:space:]]*256' <<<"$body"; then
    bad "$f: pids_limit must stay 256"
  fi
  if ! grep -Eq 'mem_limit:[[:space:]]*512m' <<<"$body"; then
    bad "$f: mem_limit must stay 512m"
  fi
  if ! grep -Eq 'cpus:[[:space:]]*1\.0' <<<"$body"; then
    bad "$f: cpus must stay 1.0"
  fi
  if grep -Eq '^[[:space:]]+shm_size:' <<<"$body"; then
    bad "$f: shm_size is forbidden; keep the default /dev/shm"
  fi
  if grep -Eq '^[[:space:]]+ulimits:' <<<"$body"; then
    bad "$f: ulimits overrides are forbidden; keep pids_limit 256"
  fi
  if grep -Eq 'oom_kill_disable:[[:space:]]*true' <<<"$body"; then
    bad "$f: oom_kill_disable is forbidden"
  fi
  if ! grep -Eq 'CDT_LISTEN:[[:space:]]*:8080' <<<"$body"; then
    bad "$f: CDT_LISTEN must stay :8080"
  fi
  if ! grep -Eq 'TZ:[[:space:]]*Asia/Taipei' <<<"$body"; then
    bad "$f: default TZ must stay Asia/Taipei"
  fi
  if ! grep -Eq 'stop_grace_period:[[:space:]]*15s' <<<"$body"; then
    bad "$f: stop_grace_period must stay 15s"
  fi
  if ! grep -Eq 'stop_signal:[[:space:]]*SIGTERM' <<<"$body"; then
    bad "$f: stop_signal must stay SIGTERM"
  fi
  if ! grep -Eq 'memswap_limit:[[:space:]]*512m' <<<"$body"; then
    bad "$f: memswap_limit must stay 512m"
  fi
  if ! grep -Eq 'CDT_DATA_DIR:[[:space:]]*/data' <<<"$body"; then
    bad "$f: CDT_DATA_DIR must stay /data"
  fi
  if ! grep -Eq '^[[:space:]]+-[[:space:]]*cdt-data:/data$' <<<"$body"; then
    bad "$f: data volume must stay named cdt-data:/data"
  fi
  if grep -Fq './data:/data' <<<"$body"; then
    bad "$f: do not bind-mount host ./data (master.key would sit on the host path)"
  fi
  if grep -Eq '^[[:space:]]+-[[:space:]]+"?/data:' <<<"$body"; then
    bad "$f: do not bind-mount host /data into the container"
  fi
  if ! grep -Eq '^name:[[:space:]]*cdt-monitor$' <<<"$body"; then
    bad "$f: Compose project name must stay cdt-monitor"
  fi
  if ! grep -Eq 'container_name:[[:space:]]*cdt-monitor$' <<<"$body"; then
    bad "$f: container_name must stay cdt-monitor"
  fi
  if ! grep -Eq 'CDT_WORKERS:[[:space:]]*2$' <<<"$body"; then
    bad "$f: CDT_WORKERS must stay 2"
  fi
  if ! grep -Fq 'IMAGE_SOURCE: https://github.com/86669666/CDT-Monitor' <<<"$body"; then
    bad "$f: IMAGE_SOURCE must stay the 86669666 fork URL"
  fi
  if grep -Eq 'network_mode:[[:space:]]*host' <<<"$body"; then
    bad "$f: network_mode: host is forbidden; keep loopback publish"
  fi
  if grep -Eq 'pid:[[:space:]]*(host|shareable|service:|container:)' <<<"$body"; then
    bad "$f: pid namespace sharing is forbidden; keep loopback publish"
  fi
  if grep -Eq 'ipc:[[:space:]]*(host|shareable|service:|container:)' <<<"$body"; then
    bad "$f: ipc namespace sharing is forbidden"
  fi
  if grep -Eq 'cgroup:[[:space:]]*host|cgroupns:[[:space:]]*host|cgroupns_mode:[[:space:]]*host' <<<"$body"; then
    bad "$f: host cgroup namespace is forbidden"
  fi
  if grep -Eq 'userns_mode:[[:space:]]*host' <<<"$body"; then
    bad "$f: userns_mode: host is forbidden"
  fi
  if grep -Eq '^[[:space:]]+runtime:' <<<"$body"; then
    bad "$f: custom runtime is forbidden on this local Compose"
  fi
  if grep -Eq '^[[:space:]]+group_add:' <<<"$body"; then
    bad "$f: group_add is forbidden"
  fi
  if grep -Eq '^[[:space:]]+cap_add:' <<<"$body"; then
    bad "$f: cap_add is forbidden; keep cap_drop ALL"
  fi
  if grep -Eq '^[[:space:]]+devices:' <<<"$body"; then
    bad "$f: devices: passthrough is forbidden"
  fi
  if grep -Eq '^[[:space:]]+sysctls:' <<<"$body"; then
    bad "$f: sysctls: is forbidden on this local Compose"
  fi
  if grep -Eq '^[[:space:]]+extra_hosts:' <<<"$body"; then
    bad "$f: extra_hosts is forbidden"
  fi
  if grep -Eq '^[[:space:]]*profiles:' <<<"$body"; then
    bad "$f: Compose profiles are forbidden; keep the single local cdt-monitor service"
  fi
  if grep -Eq '^[[:space:]]+dns(_search|_opt)?:' <<<"$body"; then
    bad "$f: custom dns/dns_search/dns_opt is forbidden"
  fi
  if grep -Eq '^[[:space:]]+mac_address:' <<<"$body"; then
    bad "$f: mac_address is forbidden"
  fi
  if grep -Eq '^[[:space:]]+hostname:' <<<"$body"; then
    bad "$f: hostname overrides are forbidden"
  fi
  if grep -Eq '^[[:space:]]+domainname:' <<<"$body"; then
    bad "$f: domainname overrides are forbidden"
  fi
  if grep -Eq 'stdin_open:[[:space:]]*true' <<<"$body"; then
    bad "$f: stdin_open: true is forbidden on this local daemon Compose"
  fi
  if grep -Eq '^[[:space:]]+tty:[[:space:]]*true' <<<"$body"; then
    bad "$f: tty: true is forbidden on this local daemon Compose"
  fi
  if grep -Eq '^[[:space:]]+env_file:' <<<"$body"; then
    bad "$f: env_file is forbidden; do not load host .env secrets into the container"
  fi
  if grep -Eq '^[[:space:]]+command:' <<<"$body"; then
    bad "$f: command: overrides are forbidden; keep the image ENTRYPOINT/CMD"
  fi
  if grep -Eq '^[[:space:]]+entrypoint:' <<<"$body"; then
    bad "$f: entrypoint: overrides are forbidden; keep /cdt-monitor"
  fi
  if grep -Eq '^[[:space:]]*networks:' <<<"$body"; then
    bad "$f: extra Compose networks are forbidden; keep the default bridge and loopback publish"
  fi
  if grep -Eq '^[[:space:]]+expose:' <<<"$body"; then
    bad "$f: expose: is forbidden; TLS stays at an external reverse proxy"
  fi
  if grep -Eq '^[[:space:]]+depends_on:' <<<"$body"; then
    bad "$f: depends_on is forbidden; this Compose has no sidecars"
  fi
  if grep -Eq 'external:[[:space:]]*true' <<<"$body"; then
    bad "$f: external: true is forbidden; keep the named cdt-data volume local"
  fi
  if grep -Fq 'docker.sock' <<<"$body"; then
    bad "$f: docker.sock bind is forbidden"
  fi
  if grep -Eq 'type:[[:space:]]*bind' <<<"$body"; then
    bad "$f: bind mounts are forbidden; keep the named cdt-data volume"
  fi
  if grep -Eq '^[[:space:]]+-[[:space:]]+"?\./' <<<"$body"; then
    bad "$f: relative host bind mounts are forbidden; keep the named cdt-data volume"
  fi
  svc_keys="$(awk '
    $0 ~ /^services:[[:space:]]*$/ { in_svc=1; next }
    in_svc && $0 ~ /^[^[:space:]]/ { in_svc=0 }
    in_svc && $0 ~ /^  [A-Za-z0-9._-]+:[[:space:]]*$/ {
      name=$1
      sub(/:$/, "", name)
      print name
    }
  ' <<<"$body")"
  if [ "$svc_keys" != "cdt-monitor" ]; then
    bad "$f: extra sidecar services are forbidden; only cdt-monitor is allowed (TLS stays at an external reverse proxy)"
  fi
  image_count="$(grep -cE '^[[:space:]]*image:' <<<"$body" || true)"
  if [ "$image_count" -ne 1 ]; then
    bad "$f: only one image: line is allowed (cdt-monitor:local, no sidecar)"
  fi
  if ! grep -Eq '^[[:space:]]+image:[[:space:]]*cdt-monitor:local$' <<<"$body"; then
    bad "$f: image: must stay cdt-monitor:local"
  fi
}

scan_vars() {
  local prod="${ENABLE_PRODUCTION_PUBLISH:-}"
  local hub="${ENABLE_DOCKERHUB_PUBLISH:-}"
  note "ENABLE_PRODUCTION_PUBLISH=${prod:-<unset>}"
  note "ENABLE_DOCKERHUB_PUBLISH=${hub:-<unset>}"
  if [ "${prod,,}" = "true" ]; then
    bad "ENABLE_PRODUCTION_PUBLISH is true; this fork must not publish"
  fi
  if [ "${hub,,}" = "true" ]; then
    bad "ENABLE_DOCKERHUB_PUBLISH is true; this fork must not publish"
  fi
}

scan_vars
scan_workflows
scan_auto_release
scan_release_binaries
scan_container
scan_widget
scan_dockerfile
scan_dockerignore
scan_dependabot
scan_npm_ci
scan_ci_verify
scan_compose
scan_checkout_credentials
scan_job_limits
scan_action_pins
scan_workflow_hygiene

if [ "$fail" -ne 0 ]; then
  note "publish-guard failed; do not set publish vars or restore GHCR/Hub login"
  exit 1
fi
note "publish-guard ok: workflow YAML stays local-verify, compose stays loopback, publish vars unset"
