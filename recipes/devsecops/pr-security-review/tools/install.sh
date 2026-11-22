#!/usr/bin/env bash
# Tools for devsecops/pr-security-review.
# The review needs git only, and the recipe has no network access, so
# nothing is downloaded: this script checks that git is there.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../../../../kits/lab-tools/lab-install.sh
source "$(dirname "${BASH_SOURCE[0]}")/lab-install.sh"

command -v git >/dev/null 2>&1 \
  || lab_die "git is missing from the sandbox image; this recipe has no network access to install it"
lab_record git "$(git --version | awk '{print $3}')" GPL-2.0

git --version
