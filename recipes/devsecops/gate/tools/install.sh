#!/usr/bin/env bash
# Pinned tools for devsecops/gate. gitleaks, osv-scanner, syft and trivy are
# baked into kits/devsecops; this adds python3 for gate.py and semgrep.
# Run by the lab runner as: bash .lab/tools/install.sh
set -euo pipefail
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../../../../kits/lab-tools/lab-install.sh
source "$(dirname "${BASH_SOURCE[0]}")/lab-install.sh"

# gate.py is stdlib-only; python3 also backs pipx.
lab_apt python3
# LGPL-2.1: installed at run time and executed, never vendored.
# Golden artifacts were regenerated with this pin.
# TODO(verify): semgrep==1.186.0 install via lab_pipx inside the sandbox;
# the golden was produced by a pip-venv install of the same pin.
lab_pipx semgrep==1.186.0 semgrep LGPL-2.1

# Prefetch the trivy vulnerability DB, Java index and checks bundle while
# install_allow is open, so scans run with --skip-db-update /
# --skip-check-update and need no trivy hosts at run time.
trivy image --download-db-only
trivy image --download-java-db-only
trivy config "$(mktemp -d)" >/dev/null

gitleaks version
osv-scanner --version
syft version
trivy version
semgrep --version
