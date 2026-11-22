#!/usr/bin/env bash
# Tag and publish a release build of the exporter.
set -euo pipefail

VERSION="${1:?usage: release.sh <version>}"

python3 -m py_compile exporter.py
git tag -a "v${VERSION}" -m "release ${VERSION}"
echo "tagged v${VERSION}; upload artifacts manually"
