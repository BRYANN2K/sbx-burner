#!/usr/bin/env bash
# Bundled demo target for devsecops/fuzzing: the toy parsers shipped in
# fixtures/. Runs only with --demo; idempotent — it just confirms the two
# harnesses are present and says where they are. The agent builds and
# fuzzes them itself.
set -euo pipefail

for dir in c-target go-target; do
  if [ ! -d "fixtures/${dir}" ]; then
    echo "demo target missing: fixtures/${dir}" >&2
    exit 1
  fi
done

echo "demo target ready:"
echo "  fixtures/c-target  length-prefixed record parser (C, off-by-one)"
echo "  fixtures/go-target field splitter FuzzParseField (Go, index panic)"
