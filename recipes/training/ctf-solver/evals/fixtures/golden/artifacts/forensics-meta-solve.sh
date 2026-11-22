#!/usr/bin/env bash
# forensics-meta: the PNG has a tEXt chunk "Comment" holding the flag in base64.
# usage: forensics-meta-solve.sh <photo.png>   prints the flag
set -euo pipefail
png="${1:-ctf-build/handout/forensics-meta/photo.png}"
if command -v exiftool >/dev/null 2>&1; then
  exiftool -s3 -Comment "$png" | base64 -d
else
  strings -n 8 "$png" | grep -A1 'tEXtComment' | tail -n 1 | base64 -d
fi
echo
