#!/usr/bin/env bash
# Returns the CTF to a clean state:  bash reset.sh
# Stops the web challenge and deletes the build directory with its flags.
# Build directory: $CTF_BUILD, else ./ctf-build. Port: $CTF_PORT, else 8081.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
build="${CTF_BUILD:-$PWD/ctf-build}"
port="${CTF_PORT:-8081}"

if [ -e "$build" ]; then
  # Only ever delete a directory that build.sh created.
  [ -f "$build/.server/ctf-build.marker" ] || { echo "refusing: $build was not made by build.sh" >&2; exit 1; }
  CTF_BUILD="$build" CTF_PORT="$port" bash "$here/serve.sh" stop
  rm -rf "$build"
fi

[ ! -e "$build" ] || { echo "reset failed: $build still exists" >&2; exit 1; }
echo "reset: build directory absent ($build)"

if curl -s -o /dev/null --max-time 2 "http://127.0.0.1:${port}/" 2>/dev/null; then
  echo "reset failed: port ${port} still answers" >&2
  exit 1
fi
echo "reset: port ${port} closed"
echo "reset ok"
