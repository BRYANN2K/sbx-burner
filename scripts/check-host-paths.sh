#!/bin/sh
# Fail when a tracked file holds a host path: a home folder, or the dotted
# form semgrep makes of one in rule ids. /home/agent/ is the sandbox user;
# /Users/tester/ and /home/tester/ are the synthetic paths tests use;
# /home/linuxbrew/ is Homebrew's official Linux prefix.
set -eu
pattern='Users\.[a-z]+\.|/Users/|/home/[a-z]+/|Documents\.Projects'
hits=$(git grep -n -I -E "$pattern" -- . \
  ':!scripts/check-host-paths.sh' ':!docs/build-plan.md' \
  | grep -v -E '/home/(agent|linuxbrew)/|/(Users|home)/tester/' || true)
if [ -n "$hits" ]; then
  printf '%s\n' "$hits"
  echo "host paths found: rewrite them (see docs/build-plan.md 3.7)" >&2
  exit 1
fi
