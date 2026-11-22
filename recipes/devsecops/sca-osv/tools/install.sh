#!/usr/bin/env bash
# Pinned tools for devsecops/sca-osv.
# osv-scanner is already in kits/devsecops; this covers sandboxes built without it.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../../../../kits/lab-tools/lab-install.sh
source "$(dirname "${BASH_SOURCE[0]}")/lab-install.sh"

OSV_SCANNER_VERSION=2.7.1

lab_gh_release google/osv-scanner "v${OSV_SCANNER_VERSION}" \
  "osv-scanner_linux_$(lab_arch amd64 arm64)" \
  "osv-scanner_SHA256SUMS" osv-scanner Apache-2.0

command -v jq >/dev/null 2>&1 || lab_apt jq

osv-scanner --version
jq --version
