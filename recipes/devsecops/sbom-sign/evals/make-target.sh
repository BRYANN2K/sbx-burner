#!/usr/bin/env bash
# Builds a throwaway Node.js project with a lockfile for a live eval:
#   bash evals/make-target.sh /tmp/sbom-demo
#   python -m lab run devsecops/sbom-sign --target /tmp/sbom-demo
#   python -m lab eval devsecops/sbom-sign --run runs/<id>
# The packages are fictional (registry.example.test). Nothing is installed.
set -euo pipefail

dest="${1:?usage: make-target.sh <new-directory>}"
[ ! -e "$dest" ] || { echo "refusing to overwrite $dest" >&2; exit 1; }
mkdir -p "$dest"

cat >"$dest/package.json" <<'JSON'
{
  "name": "sbom-demo",
  "version": "2.1.0",
  "license": "Apache-2.0",
  "dependencies": {
    "lab-http-kit": "2.3.1",
    "lab-date-utils": "1.0.4",
    "lab-geo-tiles": "1.2.0"
  }
}
JSON

cat >"$dest/package-lock.json" <<'JSON'
{
  "name": "sbom-demo",
  "version": "2.1.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "sbom-demo",
      "version": "2.1.0",
      "license": "Apache-2.0"
    },
    "node_modules/lab-http-kit": {
      "version": "2.3.1",
      "resolved": "https://registry.example.test/lab-http-kit/-/lab-http-kit-2.3.1.tgz",
      "license": "MIT"
    },
    "node_modules/lab-date-utils": {
      "version": "1.0.4",
      "resolved": "https://registry.example.test/lab-date-utils/-/lab-date-utils-1.0.4.tgz",
      "license": "Apache-2.0"
    },
    "node_modules/lab-geo-tiles": {
      "version": "1.2.0",
      "resolved": "https://registry.example.test/lab-geo-tiles/-/lab-geo-tiles-1.2.0.tgz",
      "license": "MPL-2.0"
    }
  }
}
JSON

printf '# sbom-demo\n\nFixture project for devsecops/sbom-sign live evals.\n' >"$dest/README.md"

echo "target ready: $dest (npm project with a 3-package lockfile)"
