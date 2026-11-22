#!/usr/bin/env bash
# Build the proving-ground image and export it as a docker save tarball for
# the image-kind run. Idempotent; needs docker on the host.
# run.py calls this with PG_BUILD set to proving-ground/.build/<folder>.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${PG_BUILD:-$HERE/../.build/devsecops-container-scan}"
TAG="pg/devsecops-container-scan:buster"

mkdir -p "$OUT"
docker build -t "$TAG" "$HERE/project"
docker save -o "$OUT/image.tar" "$TAG"
echo "wrote $OUT/image.tar"
