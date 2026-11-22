#!/usr/bin/env bash
# Assembles the gate target under $PG_BUILD/target: a copy of project/ plus a
# .env holding a random key pair generated here, so no secret-shaped literal
# is committed to the repository.
set -euo pipefail

TARGET="${PG_BUILD:?PG_BUILD is set by run.py}/target"

rand() { # charset length
  local s
  s="$(head -c 4096 /dev/urandom | LC_ALL=C tr -dc "$1")"
  printf '%s' "${s:0:$2}"
}
aws_id="AKIA$(rand 'A-Z2-7' 16)"
aws_secret="$(rand 'A-Za-z0-9' 40)"

rm -rf "$TARGET"
mkdir -p "$TARGET"
cp -R "project/." "$TARGET/"

{
  echo "AWS_REGION=us-east-1"
  echo "AWS_ACCESS_KEY_ID=${aws_id}"
  echo "AWS_SECRET_ACCESS_KEY=${aws_secret}"
} > "$TARGET/.env"

echo "built $TARGET"
