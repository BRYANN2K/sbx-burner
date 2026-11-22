#!/usr/bin/env bash
# Pinned tools for devsecops/secrets-scan.
# gitleaks is already in kits/devsecops; this covers sandboxes built without it.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../../../../kits/lab-tools/lab-install.sh
source "$(dirname "${BASH_SOURCE[0]}")/lab-install.sh"

GITLEAKS_VERSION=8.30.1
TRUFFLEHOG_VERSION=3.100.0

lab_gh_release gitleaks/gitleaks "v${GITLEAKS_VERSION}" \
  "gitleaks_${GITLEAKS_VERSION}_linux_$(lab_arch x64 arm64).tar.gz" \
  "gitleaks_${GITLEAKS_VERSION}_checksums.txt" gitleaks MIT

# AGPL-3.0: downloaded and executed as a separate program, never vendored.
lab_gh_release trufflesecurity/trufflehog "v${TRUFFLEHOG_VERSION}" \
  "trufflehog_${TRUFFLEHOG_VERSION}_linux_$(lab_arch amd64 arm64).tar.gz" \
  "trufflehog_${TRUFFLEHOG_VERSION}_checksums.txt" trufflehog AGPL-3.0

# jq backs the triage commands; install it only when the image lacks it.
command -v jq >/dev/null 2>&1 || lab_apt jq

gitleaks version
trufflehog --version
