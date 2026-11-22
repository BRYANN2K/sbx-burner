#!/usr/bin/env bash
# Builds a throwaway project with supply-chain weaknesses that can be proven
# offline, plus one name that only looks suspicious:
#   bash evals/make-target.sh /tmp/supply-demo
#   python -m lab run devsecops/supply-chain-risk --target /tmp/supply-demo
#   python -m lab eval devsecops/supply-chain-risk --run runs/<id>
# Nothing is installed and no script here is ever executed by the recipe.
set -euo pipefail

dest="${1:?usage: make-target.sh <new-directory>}"
[ ! -e "$dest" ] || { echo "refusing to overwrite $dest" >&2; exit 1; }
mkdir -p "$dest/node_modules/lab-native-helper/scripts" "$dest/node_modules/express"

# Weakness 1: floating versions and no lockfile.
# "expresss" looks like a typo of "express": a lead, not a proven finding.
cat >"$dest/package.json" <<'JSON'
{
  "name": "supply-demo",
  "version": "0.1.0",
  "private": true,
  "dependencies": {
    "express": "^4.19.2",
    "expresss": "latest",
    "lab-native-helper": "*"
  }
}
JSON

# Weakness 2: a dependency that runs a script at install time.
cat >"$dest/node_modules/lab-native-helper/package.json" <<'JSON'
{
  "name": "lab-native-helper",
  "version": "0.0.3",
  "license": "MIT",
  "scripts": {
    "postinstall": "node scripts/setup.js"
  }
}
JSON
printf 'console.log("lab-native-helper: benign install script");\n' \
  >"$dest/node_modules/lab-native-helper/scripts/setup.js"

cat >"$dest/node_modules/express/package.json" <<'JSON'
{
  "name": "express",
  "version": "4.19.2",
  "license": "MIT",
  "repository": "expressjs/express"
}
JSON

# Weakness 3: a Python dependency pinned to a version with a published advisory.
# PyYAML 5.3.1 is affected by CVE-2020-14343, fixed in 5.4.
mkdir -p "$dest/python"
printf 'PyYAML==5.3.1\n' >"$dest/python/requirements.txt"

echo "target ready: $dest (no lockfile, floating versions, 1 install script," \
  "1 look-alike name, 1 pinned dep with known advisories)"
