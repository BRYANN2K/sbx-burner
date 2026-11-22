#!/usr/bin/env bash
# Pinned tools for devsecops/supply-chain-risk.
# osv-scanner is already in kits/devsecops; this also covers sandboxes built
# without it. Run by the lab runner as: bash .lab/tools/install.sh
set -euo pipefail
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../../../../kits/lab-tools/lab-install.sh
source "$(dirname "${BASH_SOURCE[0]}")/lab-install.sh"

SCORECARD_VERSION=5.7.0
OSV_SCANNER_VERSION=2.7.1

lab_gh_release ossf/scorecard "v${SCORECARD_VERSION}" \
  "scorecard_${SCORECARD_VERSION}_linux_$(lab_arch amd64 arm64).tar.gz" \
  "scorecard_checksums.txt" scorecard Apache-2.0

lab_gh_release google/osv-scanner "v${OSV_SCANNER_VERSION}" \
  "osv-scanner_linux_$(lab_arch amd64 arm64)" \
  "osv-scanner_SHA256SUMS" osv-scanner Apache-2.0

# jq: distro package, used to parse registry and scorecard JSON.
command -v jq >/dev/null 2>&1 || lab_apt jq

scorecard version
osv-scanner --version
jq --version
