#!/usr/bin/env bash
# Runs the web challenge on loopback:  bash serve.sh start|stop|status
# Build directory: $CTF_BUILD, else ./ctf-build. Port: $CTF_PORT, else 8081.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
build="${CTF_BUILD:-$PWD/ctf-build}"
port="${CTF_PORT:-8081}"
data="$build/.server/web-idor/notes.json"
pid_file="$build/.server/web-idor.pid"
log="$build/.server/web-idor.log"

running() { [ -f "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null; }
answers() { curl -s -o /dev/null --max-time 2 "http://127.0.0.1:${port}/" 2>/dev/null; }

case "${1:-}" in
  start)
    [ -f "$data" ] || { echo "not built: run build.sh first" >&2; exit 3; }
    if running; then echo "already running: pid $(cat "$pid_file")"; exit 0; fi
    CTF_DATA="$data" CTF_PORT="$port" nohup python3 "$here/challenges/web-idor/app.py" >"$log" 2>&1 &
    echo "$!" >"$pid_file"
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      if answers; then echo "web-idor listening on http://localhost:${port}"; exit 0; fi
      sleep 1
    done
    echo "web-idor did not start; see $log" >&2
    exit 1
    ;;
  stop)
    if running; then kill "$(cat "$pid_file")"; fi
    rm -f "$pid_file"
    echo "web-idor stopped"
    ;;
  status)
    if running && answers; then echo "up: http://localhost:${port}"; else echo "down"; exit 1; fi
    ;;
  *)
    echo "usage: serve.sh start|stop|status" >&2
    exit 2
    ;;
esac
