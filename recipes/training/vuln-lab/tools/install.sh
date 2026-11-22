#!/usr/bin/env bash
# Tools for training/vuln-lab. The assessment needs only curl and jq (already
# in kits/base-kali) and a Docker CLI for the lab targets. The three lab
# images are pulled here so the agent step needs no egress at all.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../../../../kits/lab-tools/lab-install.sh
source "$(dirname "${BASH_SOURCE[0]}")/lab-install.sh"

# The sandbox has a private Docker Engine.
# TODO(verify): the docker CLI is present on the base-kali workload; if not,
# the Kali packages below provide it (docker-compose on Kali is Compose v2).
if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
  lab_apt docker.io docker-compose
fi

# Pull the lab images now: their registries are install-only hosts, closed
# before the agent starts. This step runs from the workspace root, so
# fixtures/compose.yaml is a relative path. The compose file needs a
# password variable just to parse; a throwaway value is enough for a pull.
compose() {
  if docker compose version >/dev/null 2>&1; then docker compose "$@"; else docker-compose "$@"; fi
}
env DVWA_DB_PASSWORD=install-only compose -f fixtures/compose.yaml pull

# Images are pinned in fixtures/compose.yaml and started by fixtures/lab.sh.
lab_record juice-shop v20.4.0 MIT
lab_record dvwa "ghcr digest, see fixtures/compose.yaml" GPL-3.0
lab_record mariadb 10.11 GPL-2.0

docker --version
curl --version | head -n 1
jq --version
