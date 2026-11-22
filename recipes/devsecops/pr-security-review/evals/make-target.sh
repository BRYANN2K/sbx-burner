#!/usr/bin/env bash
# Builds a throwaway repository with a feature branch that adds two real
# vulnerabilities and some noise that must not be reported:
#   bash evals/make-target.sh /tmp/pr-demo
#   python -m lab run devsecops/pr-security-review --target /tmp/pr-demo
#   python -m lab eval devsecops/pr-security-review --run runs/<id>
# The code is a small stdlib-only Python service. It is never started.
set -euo pipefail

dest="${1:?usage: make-target.sh <new-directory>}"
[ ! -e "$dest" ] || { echo "refusing to overwrite $dest" >&2; exit 1; }
mkdir -p "$dest/app" "$dest/tests"
cd "$dest"
git init -q -b main
git config user.email lab@example.test
git config user.name "Lab Fixture"

cat >app/db.py <<'PY'
import sqlite3


def connect(path="reports.db"):
    return sqlite3.connect(path)


def reports_for(conn, owner):
    cur = conn.execute("SELECT id, title FROM reports WHERE owner = ?", (owner,))
    return cur.fetchall()
PY

cat >app/server.py <<'PY'
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

from app import db


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlparse(self.path)
        params = parse_qs(url.query)
        if url.path == "/reports":
            owner = params.get("owner", [""])[0]
            rows = db.reports_for(db.connect(), owner)
            self.reply(200, repr(rows))
        else:
            self.reply(404, "not found")

    def reply(self, status, body):
        self.send_response(status)
        self.end_headers()
        self.wfile.write(body.encode())
PY
: >app/__init__.py
printf '# report service\n' >README.md
git add . && git commit -q -m "chore: init report service"

git checkout -q -b feature/report-export

# Vulnerability 1: SQL built by string formatting from a query parameter.
cat >>app/db.py <<'PY'


def search_reports(conn, owner, term):
    query = "SELECT id, title FROM reports WHERE owner = '%s' AND title LIKE '%%%s%%'" % (owner, term)
    return conn.execute(query).fetchall()
PY

# Vulnerability 2: file name from the request joined to the export directory.
cat >app/export.py <<'PY'
import hashlib
import os
import subprocess

EXPORT_DIR = "/srv/exports"


def read_export(name):
    path = os.path.join(EXPORT_DIR, name)
    with open(path, "rb") as fh:
        return fh.read()


def cache_key(owner, term):
    return hashlib.md5(f"{owner}:{term}".encode()).hexdigest()


def build_revision():
    return subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
PY

cat >app/server.py <<'PY'
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

from app import db, export


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlparse(self.path)
        params = parse_qs(url.query)
        if url.path == "/reports":
            owner = params.get("owner", [""])[0]
            rows = db.reports_for(db.connect(), owner)
            self.reply(200, repr(rows))
        elif url.path == "/reports/search":
            owner = params.get("owner", [""])[0]
            term = params.get("q", [""])[0]
            rows = db.search_reports(db.connect(), owner, term)
            self.reply(200, repr(rows))
        elif url.path == "/exports":
            name = params.get("name", [""])[0]
            self.reply(200, export.read_export(name).decode(errors="replace"))
        else:
            self.reply(404, "not found")

    def reply(self, status, body):
        self.send_response(status)
        self.end_headers()
        self.wfile.write(body.encode())
PY

# Noise: a test with a throwaway value, and a docs change.
cat >tests/test_export.py <<'PY'
from app import export


def test_cache_key_is_stable():
    assert export.cache_key("alice", "q3") == export.cache_key("alice", "q3")
PY
printf '# report service\n\nNew: /reports/search?owner=&q= and /exports?name=.\n' >README.md

git add . && git commit -q -m "feat: report search and export download"

echo "target ready: $dest (branch feature/report-export, base main: 2 vulnerabilities, noise)"
