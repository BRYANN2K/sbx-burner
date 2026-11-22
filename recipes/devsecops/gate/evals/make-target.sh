#!/usr/bin/env bash
# Builds a throwaway repository that should fail the gate on every check:
#   bash evals/make-target.sh ./gate-demo
#   python -m lab run devsecops/gate --target ./gate-demo
#   python -m lab eval devsecops/gate --run runs/<id>
# The token is random and assembled here, so no secret-shaped string is
# stored in this repository. Nothing is installed, built or deployed.
set -euo pipefail

dest="${1:?usage: make-target.sh <new-directory>}"
[ ! -e "$dest" ] || { echo "refusing to overwrite $dest" >&2; exit 1; }
mkdir -p "$dest/app" "$dest/k8s" "$dest/scripts"
cd "$dest"
git init -q -b main
git config user.email lab@example.test
git config user.name "Lab Fixture"

rand() { # charset length
  local s
  s="$(head -c 4096 /dev/urandom | LC_ALL=C tr -dc "$1")"
  printf '%s' "${s:0:$2}"
}
gh_token="ghp_$(rand 'A-Za-z0-9' 36)"

# Secrets: a token-shaped value in a script.
printf '#!/bin/sh\ncurl -H "Authorization: token %s" https://api.github.com/user\n' "$gh_token" >scripts/release.sh

# SCA: minimist 1.2.5 has a published advisory fixed in 1.2.6.
# Licence: lab-pdf-render is fictional and declares GPL-3.0-only.
cat >package.json <<'JSON'
{
  "name": "gate-demo",
  "version": "1.0.0",
  "license": "Apache-2.0",
  "dependencies": {
    "minimist": "1.2.5",
    "lab-pdf-render": "0.9.0"
  }
}
JSON
cat >package-lock.json <<'JSON'
{
  "name": "gate-demo",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "gate-demo",
      "version": "1.0.0",
      "license": "Apache-2.0",
      "dependencies": {
        "lab-pdf-render": "0.9.0",
        "minimist": "1.2.5"
      }
    },
    "node_modules/lab-pdf-render": {
      "version": "0.9.0",
      "resolved": "https://registry.example.test/lab-pdf-render/-/lab-pdf-render-0.9.0.tgz",
      "license": "GPL-3.0-only"
    },
    "node_modules/minimist": {
      "version": "1.2.5",
      "resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.5.tgz",
      "license": "MIT"
    }
  }
}
JSON

# SAST: a request parameter reaches a shell.
cat >app/tools.py <<'PY'
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    return subprocess.check_output("ping -c 1 " + host, shell=True)
PY

# IaC: a privileged container.
cat >k8s/deployment.yaml <<'K8S'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gate-demo
  namespace: demo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: gate-demo
  template:
    metadata:
      labels:
        app: gate-demo
    spec:
      containers:
        - name: app
          image: registry.example.test/gate-demo:1.0.0
          securityContext:
            privileged: true
K8S

git add . && git commit -q -m "feat: demo service"

echo "target ready: $dest (fails on secrets, SCA, SAST, IaC and licence; no Dockerfile, so no image scan)"
