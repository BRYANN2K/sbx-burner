#!/usr/bin/env bash
# Builds the ctf-solver target under $PG_BUILD/ctf:
#   handout/<challenge>/   what a player gets
#   .server/flags.sha256   flag hashes for check.sh
# Flags are random per build: they exist only under .build/, never here.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ctf="${PG_BUILD:?PG_BUILD is set by run.py}/ctf"
challenges=(night-shift field-photo)

command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi
}

rm -rf "$ctf"
mkdir -p "$ctf/handout" "$ctf/.server"
cp "$here/project/README.md" "$here/project/check.sh" "$ctf/"
: >"$ctf/.server/flags.sha256"

for name in "${challenges[@]}"; do
  flag="flag{$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
  mkdir -p "$ctf/handout/$name"
  cp "$here/project/challenges/$name/CHALLENGE.md" "$ctf/handout/$name/"
  CTF_FLAG="$flag" python3 "$here/project/challenges/$name/build.py" "$ctf/handout/$name"
  printf '%s  %s\n' "$(printf '%s' "$flag" | sha256)" "$name" >>"$ctf/.server/flags.sha256"
done

echo "built $ctf (${#challenges[@]} challenges)"
