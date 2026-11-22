#!/usr/bin/env bash
# Fail-closed cases for fixtures/gate.py, run anywhere:
#   bash evals/self-test.sh
# Each case must exit 2 (bad input): a gate that cannot fail must refuse to
# run. Uses throwaway directories only.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fixtures="$(cd "$here/../fixtures" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail=0

expect2() { # name command...
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "FAIL $name: exited 0"; fail=1
  elif [ "$?" = 2 ]; then echo "ok   $name: exit 2"
  else echo "FAIL $name: wrong exit code"; fail=1; fi
}

# 1. A policy without required_checks must be refused.
mkdir -p "$work/p1/artifacts"
cat > "$work/p1/policy.yaml" <<'YAML'
schema_version: "1"
sca_fail_severities: [critical, high]
sast_fail_severities: [critical, high]
iac_fail_severities: [critical, high]
container_fail_severities: [critical, high]
YAML
expect2 "no required_checks" \
  python3 "$fixtures/gate.py" --artifacts "$work/p1/artifacts" --policy "$work/p1/policy.yaml"

# 2. A required check without its *_fail_severities must be refused.
mkdir -p "$work/p2/artifacts"
sed '/^sca_fail_severities/d' "$fixtures/gate-policy.yaml" > "$work/p2/policy.yaml"
expect2 "missing sca_fail_severities" \
  python3 "$fixtures/gate.py" --artifacts "$work/p2/artifacts" --policy "$work/p2/policy.yaml"

# 3. A report without its top-level key is an error, not a pass: with the
#    shipped policy (on_check_error: fail) the gate fails instead of exiting 0.
mkdir -p "$work/p3/artifacts"
echo '{}' > "$work/p3/artifacts/osv.json"
if python3 "$fixtures/gate.py" --artifacts "$work/p3/artifacts" --policy "$fixtures/gate-policy.yaml" >/dev/null; then rc=0; else rc=$?; fi
if [ "$rc" = 1 ] && python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); sys.exit(0 if r["checks"]["sca"]["status"] == "error" else 1)' "$work/p3/artifacts/gate-result.json"; then
  echo "ok   empty osv report: gate failed, sca status=error"
else
  echo "FAIL empty osv report: rc=$rc"; fail=1
fi

[ "$fail" = 0 ] && echo "self-test: all cases fail closed" || exit 1
