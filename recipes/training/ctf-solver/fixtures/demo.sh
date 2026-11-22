#!/usr/bin/env bash
# Bundled demo lab for training/ctf-solver: the ctf-lab challenges shipped
# in fixtures/. Runs only with --demo; idempotent — build.sh refuses to
# overwrite an existing build dir and serve.sh reports an already-running
# challenge, so the steps are skipped on a second run.
set -euo pipefail

export CTF_BUILD="${CTF_BUILD:-$PWD/ctf-build}"

if [ ! -d "$CTF_BUILD/handout" ]; then
  bash fixtures/build.sh "$CTF_BUILD"
else
  echo "ctf-build already exists: $CTF_BUILD"
fi

if bash fixtures/serve.sh status >/dev/null 2>&1; then
  echo "web-idor already running"
else
  bash fixtures/serve.sh start
fi

echo "demo lab ready: handouts in $CTF_BUILD/handout, web-idor on localhost:8081"
echo "check flags with: bash fixtures/check.sh <challenge> <flag>"
