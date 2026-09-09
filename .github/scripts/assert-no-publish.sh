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
  local f body
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

scan_dockerfile() {
  local f="Dockerfile"
  require_file "$f" || return
  local body
  body="$(strip_comments "$f")"
  if ! grep -Fq 'ARG IMAGE_SOURCE=https://github.com/86669666/CDT-Monitor' <<<"$body"; then
    bad "$f: default IMAGE_SOURCE must stay https://github.com/86669666/CDT-Monitor"
  fi
  if grep -Eq 'wang4386' <<<"$body"; then
    bad "$f: do not default image source to upstream wang4386"
  fi
  if grep -Eq '(^|[[:space:]])--push([[:space:]]|$)' <<<"$body"; then
    bad "$f: --push is forbidden in the Dockerfile"
  fi
}

scan_compose() {
  local f="docker-compose.yml"
  require_file "$f" || return
  local body images
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
  if grep -Eq '^[[:space:]]*-[[:space:]]*"?[0-9]+:[0-9]+' <<<"$body"; then
    bad "$f: host port without 127.0.0.1 publishes 0.0.0.0"
  fi
  if grep -Eq '^[[:space:]]+(CDT_MASTER_KEY|CDT_TRUSTED_PROXIES|ENABLE_PRODUCTION_PUBLISH|ENABLE_DOCKERHUB_PUBLISH|DOCKER_USERNAME|DOCKER_PASSWORD|ANDROID_KEYSTORE_BASE64|ANDROID_KEYSTORE_PASSWORD|ANDROID_KEY_ALIAS|ANDROID_KEY_PASSWORD):' <<<"$body"; then
    bad "$f: do not put publish vars, cloud secrets, or unimplemented CDT_TRUSTED_PROXIES in Compose"
  fi
  if grep -Eiq '^[[:space:]]+([A-Z0-9_]*ACCESS_KEY[A-Z0-9_]*|[A-Z0-9_]*SECRET[A-Z0-9_]*|SMTP_PASSWORD|TELEGRAM_TOKEN|BOT_TOKEN):' <<<"$body"; then
    bad "$f: do not put Aliyun/notify secrets in Compose env"
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
scan_dockerfile
scan_compose
scan_checkout_credentials

if [ "$fail" -ne 0 ]; then
  note "publish-guard failed; do not set publish vars or restore GHCR/Hub login"
  exit 1
fi
note "publish-guard ok: workflow YAML stays local-verify, compose stays loopback, publish vars unset"
