#!/usr/bin/env bash
# Writes a small Dockerfile build context for a live eval:
#   bash evals/make-target.sh ./scan-demo
#   python -m lab run devsecops/container-scan --target ./scan-demo
#   python -m lab eval devsecops/container-scan --run runs/<id>
# The base image is an end-of-life Debian with known CVEs, so both scanners
# must report critical/high findings. Building needs a Docker Hub pull of
# debian:buster-slim; nothing else leaves the sandbox.
set -euo pipefail

dest="${1:?usage: make-target.sh <new-directory>}"
[ ! -e "$dest" ] || { echo "refusing to overwrite $dest" >&2; exit 1; }
mkdir -p "$dest"

cat >"$dest/Dockerfile" <<'DOCKER'
FROM debian:buster-slim
COPY hello.sh /opt/hello.sh
CMD ["/bin/bash", "/opt/hello.sh"]
DOCKER

cat >"$dest/hello.sh" <<'SH'
#!/bin/bash
echo "scan demo image: nothing runs during the lab, this file is inert"
SH

echo "target ready: $dest (Dockerfile FROM debian:buster-slim, EOL on purpose)"
