#!/usr/bin/env bash
# Builds a throwaway repository with planted fake secrets for a live eval:
#   bash evals/make-target.sh /tmp/leaky-repo
#   python -m lab run devsecops/secrets-scan --target /tmp/leaky-repo
#   python -m lab eval devsecops/secrets-scan --run runs/<id>
# The values are random and assembled here, so no secret-shaped string is
# stored in this repository.
set -euo pipefail

dest="${1:?usage: make-target.sh <new-directory>}"
[ ! -e "$dest" ] || { echo "refusing to overwrite $dest" >&2; exit 1; }
mkdir -p "$dest"
cd "$dest"
git init -q
git config user.email lab@example.test
git config user.name "Lab Fixture"

rand() { # charset length
  local s
  s="$(head -c 4096 /dev/urandom | LC_ALL=C tr -dc "$1")"
  printf '%s' "${s:0:$2}"
}
aws_id="AKIA$(rand 'A-Z2-7' 16)"
aws_secret="$(rand 'A-Za-z0-9' 40)"
gh_token="ghp_$(rand 'A-Za-z0-9' 36)"
fixture_key="$(rand 'A-Za-z0-9' 51)"

printf '# demo service\n' >README.md
git add . && git commit -q -m "chore: init"

# Leak 1: cloud key committed, then "removed" (still in history).
printf 'AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n' "$aws_id" "$aws_secret" >.env
git add -f .env && git commit -q -m "feat: add deploy config"
git rm -q .env && git commit -q -m "fix: remove env file"

# Leak 2: token still present in HEAD.
mkdir -p scripts
printf '#!/bin/sh\ncurl -H "Authorization: token %s" https://api.github.com/user\n' "$gh_token" >scripts/release.sh
git add . && git commit -q -m "feat: release script"

# False positive: a random key-shaped value gitleaks really reports
# (generic-api-key), in a test fixture whose context marks it as a dummy.
mkdir -p tests
cat >tests/test_client.py <<PY
import os

API_KEY = "$fixture_key"


def test_client_uses_fixture_key():
    # Dummy credential for the mocked transport; never a real service.
    assert API_KEY
PY
git add . && git commit -q -m "test: client fixture"

echo "target ready: $dest (2 real-looking leaks, 1 test-fixture false positive)"
