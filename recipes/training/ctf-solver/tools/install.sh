#!/usr/bin/env bash
# Tools for training/ctf-solver. All are Kali packages: the version is the one
# Kali rolling ships on the day of the run, recorded below with dpkg-query.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../../../../kits/lab-tools/lab-install.sh
source "$(dirname "${BASH_SOURCE[0]}")/lab-install.sh"

packages=(
  libimage-exiftool-perl # forensics: metadata (Artistic/GPL, run only)
  binwalk                # forensics: embedded files (MIT)
  xxd                    # hex dumps (Vim licence)
  file                   # file type (BSD-2-Clause)
  binutils               # strings, readelf, objdump (GPL-3.0, run only)
  gdb                    # rev / pwn-lite: debugger (GPL-3.0, run only)
  radare2                # rev: disassembly (LGPL-3.0, run only)
  netcat-openbsd         # talk to a scope host (BSD)
  python3-pycryptodome   # crypto primitives for solve scripts (BSD-2-Clause)
)
lab_apt "${packages[@]}"

dpkg-query -W -f='${Package} ${Version}\n' "${packages[@]}"
python3 --version
curl --version | head -n 1
