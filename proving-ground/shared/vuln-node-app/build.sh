#!/usr/bin/env bash
# Build the shared group-C Node app.
#
# Idempotent:
#   1. two test accounts with random passwords -> seed-users.json (baked into
#      the image) and credentials.json (for api-greybox's path mount)
#   2. image pg/vuln-node-app:latest, built from a context under $PG_BUILD
#   3. a source copy under "$PG_BUILD/app" for path-kind mounts
#
# The app only ever runs through burner / the sandbox (--target-image +
# --target-port). Nothing here starts a container on the host.
#
# Host runtime, picked like the runner does: $LAB_HOST_RUNTIME (docker or
# container), else Docker when `docker info` answers, else Apple container
# when `container system status` answers. The runner saves the image from
# the same runtime.
#
# run.py sets PG_BUILD=proving-ground/.build/<folder>; a manual run falls back
# to proving-ground/.build/vuln-node-app.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
build_dir="${PG_BUILD:-$here/../../.build/vuln-node-app}"
image="pg/vuln-node-app:latest"

runtime_ok() {
  case "$1" in
    docker) command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 ;;
    container) command -v container >/dev/null 2>&1 && container system status >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}

pick_runtime() {
  local forced="${LAB_HOST_RUNTIME:-}"
  if [ -n "$forced" ]; then
    case "$forced" in
      docker | container) ;;
      *) echo "LAB_HOST_RUNTIME=$forced: use docker or container" >&2; return 1 ;;
    esac
    runtime_ok "$forced" || { echo "LAB_HOST_RUNTIME=$forced is not running on this host" >&2; return 1; }
    echo "$forced"
    return
  fi
  for rt in docker container; do
    if runtime_ok "$rt"; then echo "$rt"; return; fi
  done
  echo "no host container runtime: start Docker (or colima) or Apple container (container system start)" >&2
  return 1
}

rand_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

runtime="$(pick_runtime)"
rm -rf "$build_dir/ctx" "$build_dir/app"
mkdir -p "$build_dir/ctx" "$build_dir/app"

users="[
  {\"username\": \"tester-a@corner-shop.test\", \"name\": \"Tester A\", \"password\": \"$(rand_hex 12)\"},
  {\"username\": \"tester-b@corner-shop.test\", \"name\": \"Tester B\", \"password\": \"$(rand_hex 12)\"}
]"

cp "$here"/server.js "$here"/package.json "$here"/package-lock.json \
   "$here"/openapi.yaml "$here"/Dockerfile "$build_dir/ctx/"
printf '%s\n' "$users" >"$build_dir/ctx/seed-users.json"
# Build output goes to a log; `container build -q` hangs without a TTY
# (container CLI 1.0.0), so both runtimes use plain progress.
log="$build_dir/image-build.log"
case "$runtime" in
  docker) docker build -t "$image" "$build_dir/ctx" >"$log" 2>&1 ;;
  container) container build --progress plain -t "$image" "$build_dir/ctx" >"$log" 2>&1 ;;
esac

# Source-only copy for path-kind mounts (no node_modules, no README: the
# README documents the app and stays out of the mounted tree), plus the two
# test accounts in the shape api-greybox reads.
cp "$here"/server.js "$here"/package.json "$here"/package-lock.json \
   "$here"/openapi.yaml "$here"/Dockerfile "$build_dir/ctx/seed-users.json" "$build_dir/app/"
printf '%s\n' "$users" | python3 -c '
import json, sys
print(json.dumps([{"username": u["username"], "password": u["password"]} for u in json.load(sys.stdin)], indent=2))
' >"$build_dir/app/credentials.json"

echo "built $image with $runtime; accounts in $build_dir/app/credentials.json"
