#!/usr/bin/env bash
# Pinned tools for devsecops/license-compliance.
# syft is already in kits/devsecops; this covers sandboxes built without it.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../../../../kits/lab-tools/lab-install.sh
source "$(dirname "${BASH_SOURCE[0]}")/lab-install.sh"

SYFT_VERSION=1.57.2

lab_gh_release anchore/syft "v${SYFT_VERSION}" \
  "syft_${SYFT_VERSION}_linux_$(lab_arch amd64 arm64).tar.gz" \
  "syft_${SYFT_VERSION}_checksums.txt" syft Apache-2.0

# fixtures/license-check.py needs python3 (standard library only).
missing=()
command -v jq >/dev/null 2>&1 || missing+=(jq)
command -v python3 >/dev/null 2>&1 || missing+=(python3)
if [ "${#missing[@]}" -gt 0 ]; then lab_apt "${missing[@]}"; fi

syft version
jq --version
python3 --version
