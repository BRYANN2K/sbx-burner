#!/usr/bin/env bash
# Installs the pinned tools for this recipe inside the sandbox.
# Run by the lab runner as: bash .lab/tools/install.sh
set -euo pipefail
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../../kits/lab-tools/lab-install.sh
source "$(dirname "${BASH_SOURCE[0]}")/lab-install.sh"

# Example: a pinned GitHub release, verified against the upstream checksums.
# lab_gh_release owner/repo v1.2.3 \
#   "tool_1.2.3_linux_$(lab_arch amd64 arm64).tar.gz" "tool_1.2.3_checksums.txt" tool MIT

lab_log "nothing to install for the template"
