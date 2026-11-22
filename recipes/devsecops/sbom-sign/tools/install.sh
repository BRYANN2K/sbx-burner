#!/usr/bin/env bash
# Pinned tools for devsecops/sbom-sign.
# syft and cosign are already in kits/devsecops; this covers sandboxes built
# without the kit.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../../../../kits/lab-tools/lab-install.sh
source "$(dirname "${BASH_SOURCE[0]}")/lab-install.sh"

SYFT_VERSION=1.57.2
COSIGN_VERSION=3.1.4

lab_gh_release anchore/syft "v${SYFT_VERSION}" \
  "syft_${SYFT_VERSION}_linux_$(lab_arch amd64 arm64).tar.gz" \
  "syft_${SYFT_VERSION}_checksums.txt" syft Apache-2.0

lab_gh_release sigstore/cosign "v${COSIGN_VERSION}" \
  "cosign-linux-$(lab_arch amd64 arm64)" \
  "cosign_checksums.txt" cosign Apache-2.0

command -v jq >/dev/null 2>&1 || lab_apt jq

syft version
cosign version
jq --version
