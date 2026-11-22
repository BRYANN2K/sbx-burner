#!/usr/bin/env bash
# Tools for training/ctf-lab. The lab needs bash, python3 and curl (already in
# kits/base-kali). The packages below are for the operator's solvability
# checks. Distro packages: the version is the one Kali rolling ships.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../../../../kits/lab-tools/lab-install.sh
source "$(dirname "${BASH_SOURCE[0]}")/lab-install.sh"

# ExifTool is dual Artistic/GPL: installed and executed only, never vendored.
# binutils provides strings, the skill's metadata fallback.
lab_apt libimage-exiftool-perl xxd file binutils

python3 --version
curl --version | head -n 1
exiftool -ver
file --version | head -n 1
strings --version | head -n 1
