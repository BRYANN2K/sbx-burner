#!/usr/bin/env bash
# Builds a throwaway project with one pinned package that has known
# advisories:
#   bash evals/make-target.sh /tmp/osv-demo
#   python -m lab run devsecops/sca-osv --target /tmp/osv-demo
#   python -m lab eval devsecops/sca-osv --run runs/<id>
set -euo pipefail

dest="${1:?usage: make-target.sh <new-directory>}"
[ ! -e "$dest" ] || { echo "refusing to overwrite $dest" >&2; exit 1; }
mkdir -p "$dest"

# requests 2.25.0 carries several published advisories; osv-scanner lists
# them grouped under .results[].packages[].groups in artifacts/osv.json.
printf 'requests==2.25.0\n' >"$dest/requirements.txt"

echo "target ready: $dest (1 pinned package with known advisories)"
