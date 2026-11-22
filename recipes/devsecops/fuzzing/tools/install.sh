#!/usr/bin/env bash
# Pinned tools for devsecops/fuzzing: clang with libFuzzer, the Go toolchain
# and AFL++ (AGPL-3.0, run only). All come from Debian stable packages; the
# distribution pins the versions.
# Run by the lab runner as: bash .lab/tools/install.sh
set -euo pipefail
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../../../../kits/lab-tools/lab-install.sh
source "$(dirname "${BASH_SOURCE[0]}")/lab-install.sh"

# clang + libclang-rt-dev: distro compiler-rt ships libclang_rt.fuzzer-*.a.
# golang: distro toolchain, `go test -fuzz` needs >= 1.18.
# afl++: AGPL-3.0, 4.21c on Debian trixie; installed and executed, never vendored.
# TODO(verify): trixie ships afl++ 4.21c-5; upstream 5.03c is only in
# forky/sid — confirm the installed version inside the sandbox.
lab_apt clang libclang-rt-dev golang afl++

clang --version
go version
afl-fuzz -h 2>&1 | head -3 || true
