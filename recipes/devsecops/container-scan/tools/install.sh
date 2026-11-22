#!/usr/bin/env bash
# Pinned tools for devsecops/container-scan.
# trivy and grype are already in kits/devsecops; this covers sandboxes built
# without the kit.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../../../../kits/lab-tools/lab-install.sh
source "$(dirname "${BASH_SOURCE[0]}")/lab-install.sh"

TRIVY_VERSION=0.76.2
GRYPE_VERSION=0.122.1

lab_gh_release aquasecurity/trivy "v${TRIVY_VERSION}" \
  "trivy_${TRIVY_VERSION}_Linux-$(lab_arch 64bit ARM64).tar.gz" \
  "trivy_${TRIVY_VERSION}_checksums.txt" trivy Apache-2.0

lab_gh_release anchore/grype "v${GRYPE_VERSION}" \
  "grype_${GRYPE_VERSION}_linux_$(lab_arch amd64 arm64).tar.gz" \
  "grype_${GRYPE_VERSION}_checksums.txt" grype Apache-2.0

missing=()
command -v docker >/dev/null 2>&1 || missing+=(docker.io)
command -v jq >/dev/null 2>&1 || missing+=(jq)
command -v python3 >/dev/null 2>&1 || missing+=(python3)
if [ "${#missing[@]}" -gt 0 ]; then lab_apt "${missing[@]}"; fi

# Prefetch both vulnerability databases while install_allow is open so
# scans run with --skip-db-update and GRYPE_DB_AUTO_UPDATE=false and need
# no database hosts at run time.
trivy image --download-db-only
trivy image --download-java-db-only
grype db update

trivy version
grype version
docker --version
