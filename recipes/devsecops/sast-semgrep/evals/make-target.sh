#!/usr/bin/env bash
# Builds a throwaway Flask app with planted vulnerable code:
#   bash evals/make-target.sh /tmp/sast-demo
#   python -m lab run devsecops/sast-semgrep --target /tmp/sast-demo
#   python -m lab eval devsecops/sast-semgrep --run runs/<id>
set -euo pipefail

dest="${1:?usage: make-target.sh <new-directory>}"
[ ! -e "$dest" ] || { echo "refusing to overwrite $dest" >&2; exit 1; }
mkdir -p "$dest/tests"

# Finding 1: request data reaches a shell command. Finding 2: debug=True.
# diag() validates the input first: the rule still reports it (the
# regex is not a declared sanitizer) and the agent should dismiss it.
cat >"$dest/app.py" <<'PY'
import re
import subprocess
import flask

app = flask.Flask(__name__)


@app.route("/ping")
def ping():
    host = flask.request.args.get("host", "127.0.0.1")
    out = subprocess.run("ping -c1 " + host, shell=True, capture_output=True)
    return out.stdout


@app.route("/diag")
def diag():
    host = flask.request.args.get("host", "")
    if not re.fullmatch(r"[a-zA-Z0-9.-]{1,64}", host):
        return "bad host", 400
    out = subprocess.run("ping -c1 " + host, shell=True, capture_output=True)
    return out.stdout


@app.route("/health")
def health():
    return {"ok": True}


if __name__ == "__main__":
    app.run(debug=True)
PY

# Finding 3: fixed temp path opened for writing.
cat >"$dest/tools.py" <<'PY'
import os


def store_report(data):
    # writes a report to a fixed temp path
    with open("/tmp/report.txt", "w") as fh:
        fh.write(data)
PY

# Same vulnerable pattern in test code. Semgrep's default ignores skip
# tests/; if scanned anyway it is test code and must be dismissed.
cat >"$dest/tests/test_ping.py" <<'PY'
import subprocess
import flask


def build_ping_for_test():
    # helper for the manual integration test only
    host = flask.request.args.get("host")
    return subprocess.run("ping -c1 " + host, shell=True, capture_output=True)
PY

echo "target ready: $dest (3 real hits, 1 sanitised hit, 1 test-code file)"
