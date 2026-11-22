#!/usr/bin/env bash
# Builds the secrets-scan target: a small git repo with history under
# $PG_BUILD/repo. Key-shaped values are random and generated here, so no
# secret-shaped literal is ever committed to this repository.
set -euo pipefail

REPO="${PG_BUILD:?PG_BUILD is set by run.py}/repo"

rand() { # charset length
  local s
  s="$(head -c 4096 /dev/urandom | LC_ALL=C tr -dc "$1")"
  printf '%s' "${s:0:$2}"
}
aws_id="AKIA$(rand 'A-Z2-7' 16)"
aws_secret="$(rand 'A-Za-z0-9' 40)"
# Digits plus letters that spell no word: gitleaks drops generic-api-key
# matches containing a stopword, and this value must always be reported.
fixture_key="$(rand 'GJKQVWXZgjkqvwxz0-9' 48)"

rm -rf "$REPO"
mkdir -p "$REPO"
cp -R "project/." "$REPO/"
cd "$REPO"

git init -q -b main
git config user.email "pg@example.invalid"
git config user.name "proving-ground"
git add -A
git commit -qm "import billing exporter"

{
  echo "AWS_REGION=us-east-1"
  echo "AWS_ACCESS_KEY_ID=${aws_id}"
  echo "AWS_SECRET_ACCESS_KEY=${aws_secret}"
} > .env
git add .env
git commit -qm "wip: local env"

git rm -q .env
printf 'AWS_ACCESS_KEY_ID=<your-key-id>\nAWS_SECRET_ACCESS_KEY=<your-secret>\n' > .env.example
git add .env.example
git commit -qm "remove .env; add .env.example"

# Unit test with a random key-shaped value for a mocked client.
mkdir -p tests
cat > tests/test_exporter.py <<PY
from exporter import summarize

API_KEY = "${fixture_key}"


def test_summarize_with_mocked_upload():
    # Mocked upload transport; the key only has to be non-empty.
    assert API_KEY
    assert summarize([{"account": "a", "units": "2"}]) == {"a": 2.0}
PY
git add tests/test_exporter.py
git commit -qm "test: exporter summary"

echo "built $REPO ($(git log --oneline | wc -l | tr -d ' ') commits)"
