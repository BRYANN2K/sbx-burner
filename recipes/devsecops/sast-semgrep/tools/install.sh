#!/usr/bin/env bash
# Pinned tools for devsecops/sast-semgrep.
# semgrep is LGPL-2.1: installed at run time and executed only, never vendored.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../../../../kits/lab-tools/lab-install.sh
source "$(dirname "${BASH_SOURCE[0]}")/lab-install.sh"

SEMGREP_VERSION=1.186.0

lab_pipx "semgrep==${SEMGREP_VERSION}" semgrep LGPL-2.1

command -v jq >/dev/null 2>&1 || lab_apt jq

semgrep --version
jq --version
