#!/usr/bin/env bash
# Builds the CTF into a build directory:  bash build.sh [build-dir]
# Default build directory: $CTF_BUILD, else ./ctf-build.
#
#   <build>/handout/<challenge>/   what a player gets (statement + files)
#   <build>/.server/               operator side: flag hashes, web data, pid
#
# Flags are random per build. They exist only in the build directory, never
# in this repository. check.sh compares SHA-256 hashes.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
build="${1:-${CTF_BUILD:-$PWD/ctf-build}}"
challenges=(web-idor crypto-xor forensics-meta)

[ ! -e "$build" ] || { echo "refusing to overwrite $build (run reset.sh first)" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi
}

mkdir -p "$build/handout" "$build/.server"
chmod 700 "$build/.server"
: >"$build/.server/ctf-build.marker"

for name in "${challenges[@]}"; do
  flag="flag{$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
  mkdir -p "$build/handout/$name" "$build/.server/$name"
  cp "$here/challenges/$name/CHALLENGE.md" "$build/handout/$name/CHALLENGE.md"
  CTF_FLAG="$flag" python3 "$here/challenges/$name/build.py" \
    "$build/handout/$name" "$build/.server/$name"
  printf '%s  %s\n' "$(printf '%s' "$flag" | sha256)" "$name" >>"$build/.server/flags.sha256"
  echo "built $name"
done
chmod 600 "$build/.server/flags.sha256"

echo "build ok: ${#challenges[@]} challenges in $build"
