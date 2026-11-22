#!/usr/bin/env bash
# Tools for foundation/triage-and-report: jq and python3 from Debian.
# Docker's Debian agent image usually ships them; install only what is missing.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../../../../kits/lab-tools/lab-install.sh
source "$(dirname "${BASH_SOURCE[0]}")/lab-install.sh"

missing=()
for bin in jq python3; do
  if command -v "$bin" >/dev/null 2>&1; then
    lab_record "$bin" "present" "distro"
  else
    missing+=("$bin")
  fi
done
if [ "${#missing[@]}" -gt 0 ]; then
  lab_apt "${missing[@]}"
fi

jq --version
python3 --version
