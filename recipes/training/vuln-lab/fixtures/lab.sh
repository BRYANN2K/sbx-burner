#!/usr/bin/env bash
# Lifecycle of the training/vuln-lab targets.
#   bash fixtures/lab.sh up       pull and start Juice Shop and DVWA
#   bash fixtures/lab.sh wait     block until both answer (default 300 s)
#   bash fixtures/lab.sh status   list the containers
#   bash fixtures/lab.sh reset    stop everything and delete the volumes
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
env_file="${here}/.env"
juice_url="http://localhost:3000/rest/admin/application-version"
# setup.php answers 200 even before the DVWA database is created.
dvwa_url="http://localhost:8081/setup.php"

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose --env-file "$env_file" -f "${here}/compose.yaml" "$@"
  else
    docker-compose --env-file "$env_file" -f "${here}/compose.yaml" "$@"
  fi
}

# The database password is random per lab and never stored in the repository.
ensure_env() {
  [ -f "$env_file" ] && return 0
  local pw
  pw="$(head -c 4096 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9')"
  (umask 077 && printf 'DVWA_DB_PASSWORD=%s\n' "${pw:0:24}" >"$env_file")
}

http_ok() { # url
  [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$1" || true)" = "200" ]
}

case "${1:-}" in
  up)
    ensure_env
    compose up -d
    ;;
  wait)
    deadline=$((SECONDS + ${LAB_WAIT_SECONDS:-300}))
    until http_ok "$juice_url" && http_ok "$dvwa_url"; do
      if [ "$SECONDS" -ge "$deadline" ]; then
        echo "lab not ready after ${LAB_WAIT_SECONDS:-300} s" >&2
        compose ps >&2 || true
        exit 1
      fi
      sleep 5
    done
    echo "ready: juice-shop http://localhost:3000"
    echo "ready: dvwa http://localhost:8081"
    ;;
  status)
    ensure_env
    compose ps
    ;;
  reset)
    ensure_env
    compose down -v --remove-orphans
    rm -f "$env_file"
    if http_ok "$juice_url" || http_ok "$dvwa_url"; then
      echo "reset failed: a target still answers" >&2
      exit 1
    fi
    echo "reset: containers and volumes removed, ports 3000 and 8081 closed"
    ;;
  *)
    echo "usage: lab.sh up|wait|status|reset" >&2
    exit 2
    ;;
esac
