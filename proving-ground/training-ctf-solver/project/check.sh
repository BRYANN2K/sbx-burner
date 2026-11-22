#!/usr/bin/env bash
# Checks a flag:  bash check.sh <challenge> <flag|->
# "-" reads the flag from stdin so it stays out of the process list.
# Exit codes: 0 correct, 1 wrong, 2 usage or unknown challenge, 3 not built.
set -euo pipefail

root="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
name="${1:-}"
flag="${2:-}"
if [ -z "$name" ] || [ -z "$flag" ]; then
  echo "usage: check.sh <challenge> <flag|->" >&2
  exit 2
fi
if [ "$flag" = "-" ]; then
  IFS= read -r flag || true
fi

sums="$root/.server/flags.sha256"
[ -f "$sums" ] || { echo "NOT-BUILT no flag hashes in $root" >&2; exit 3; }

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi
}

expected="$(awk -v n="$name" '$2 == n {print $1; exit}' "$sums")"
[ -n "$expected" ] || { echo "UNKNOWN $name" >&2; exit 2; }

if [ "$(printf '%s' "$flag" | sha256)" = "$expected" ]; then
  echo "OK $name"
else
  echo "WRONG $name"
  exit 1
fi
