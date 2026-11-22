#!/usr/bin/env bash
# Builds the pr-security-review target: a git repo under $PG_BUILD/repo with
# the base branch `main` (project/base) and the pull-request branch
# `feature/mobile-sessions` checked out (project/pr-1, then project/pr-2).
# The repo is rebuilt from scratch on every run; no .git is committed here.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="${PG_BUILD:?PG_BUILD is set by run.py}/repo"

g() {
  git -c core.hooksPath=/dev/null -c commit.gpgsign=false \
    -c user.name="Timesheet Dev" -c user.email="dev@example.invalid" "$@"
}

rm -rf "$repo"
mkdir -p "$repo"
cp -R "$here/project/base/." "$repo/"
cd "$repo"

g init -q -b main
g add -A
g commit -qm "feat: timesheet API with signed sessions"

g checkout -q -b feature/mobile-sessions
cp -R "$here/project/pr-1/." "$repo/"
g add -A
g commit -qm "feat: accept sessions from the mobile app"

cp -R "$here/project/pr-2/." "$repo/"
g add -A
g commit -qm "feat: ETag on entries and a version endpoint"

echo "built $repo (base main, branch feature/mobile-sessions, $(g rev-list --count main..HEAD) commits)"
