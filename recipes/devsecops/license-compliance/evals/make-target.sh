#!/usr/bin/env bash
# Builds a throwaway Node.js project whose lockfile declares a mix of licences:
#   bash evals/make-target.sh /tmp/licence-demo
#   python -m lab run devsecops/license-compliance --target /tmp/licence-demo
#   python -m lab eval devsecops/license-compliance --run runs/<id>
# The packages are fictional (registry.example.test). Nothing is installed.
set -euo pipefail

dest="${1:?usage: make-target.sh <new-directory>}"
[ ! -e "$dest" ] || { echo "refusing to overwrite $dest" >&2; exit 1; }
mkdir -p "$dest"

cat >"$dest/package.json" <<'JSON'
{
  "name": "licence-demo",
  "version": "1.0.0",
  "license": "Apache-2.0",
  "dependencies": {
    "lab-http-kit": "2.3.1",
    "lab-date-utils": "1.0.4",
    "lab-pdf-render": "0.9.0",
    "lab-legacy-codec": "3.1.0",
    "lab-geo-tiles": "1.2.0"
  },
  "devDependencies": {
    "lab-test-reporter": "4.0.0"
  }
}
JSON

# entry <name> <version> <licence-or-empty> [dev]
entry() {
  local name="$1" version="$2" licence="$3" dev="${4:-}"
  printf '    "node_modules/%s": {\n      "version": "%s",\n' "$name" "$version"
  printf '      "resolved": "https://registry.example.test/%s/-/%s-%s.tgz"' "$name" "$name" "$version"
  [ -z "$licence" ] || printf ',\n      "license": "%s"' "$licence"
  [ -z "$dev" ] || printf ',\n      "dev": true'
  printf '\n    }'
}

{
  printf '{\n  "name": "licence-demo",\n  "version": "1.0.0",\n  "lockfileVersion": 3,\n  "requires": true,\n  "packages": {\n'
  printf '    "": {\n      "name": "licence-demo",\n      "version": "1.0.0",\n      "license": "Apache-2.0"\n    },\n'
  entry lab-http-kit 2.3.1 MIT; printf ',\n'
  entry lab-date-utils 1.0.4 "(MIT OR GPL-3.0-only)"; printf ',\n'
  entry lab-pdf-render 0.9.0 GPL-3.0-only; printf ',\n'
  entry lab-legacy-codec 3.1.0 ""; printf ',\n'
  entry lab-geo-tiles 1.2.0 MPL-2.0; printf ',\n'
  entry lab-test-reporter 4.0.0 AGPL-3.0-only dev; printf '\n'
  printf '  }\n}\n'
} >"$dest/package-lock.json"

echo "target ready: $dest (1 denied shipped licence, 1 unknown, 1 review, 1 denied dev-only)"
