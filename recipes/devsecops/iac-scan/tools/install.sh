#!/usr/bin/env bash
# Pinned tools for devsecops/iac-scan.
# trivy is already in kits/devsecops; this covers sandboxes built without it.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../../../../kits/lab-tools/lab-install.sh
source "$(dirname "${BASH_SOURCE[0]}")/lab-install.sh"

TRIVY_VERSION=0.76.2
CHECKOV_VERSION=3.4.6

lab_gh_release aquasecurity/trivy "v${TRIVY_VERSION}" \
  "trivy_${TRIVY_VERSION}_Linux-$(lab_arch 64bit ARM64).tar.gz" \
  "trivy_${TRIVY_VERSION}_checksums.txt" trivy Apache-2.0

command -v jq >/dev/null 2>&1 || lab_apt jq

# Optional second scanner. Set LAB_SKIP_CHECKOV=1 to skip the PyPI install.
if [ -z "${LAB_SKIP_CHECKOV:-}" ]; then
  lab_pipx "checkov==${CHECKOV_VERSION}" checkov Apache-2.0
fi

trivy --version
jq --version
if command -v checkov >/dev/null 2>&1; then checkov --version; fi
