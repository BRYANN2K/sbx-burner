---
name: supply-chain-audit
description: Audit a project's third-party dependencies for supply-chain risk with osv-scanner, OpenSSF Scorecard and registry metadata. Use when asked to review dependencies, find install scripts, unpinned versions or typosquat-suspicious package names.
---

# Supply-chain dependency audit

Check every dependency of the target for: code run at install time, unpinned
versions, missing lockfiles, names that look like a popular package, registry
health and repository score. Proven risks are findings; suspicions are
hypotheses.

## 1. Inventory the dependencies

```bash
mkdir -p evidence/artifacts
cd /home/agent/target

# Manifest files that declare dependencies:
find . -name node_modules -prune -o -type f \
  \( -name 'package.json' -o -name 'package-lock.json' -o -name 'yarn.lock' \
   -o -name 'pnpm-lock.yaml' -o -name 'requirements*.txt' -o -name 'pyproject.toml' \
   -o -name 'go.mod' -o -name 'Cargo.toml' -o -name 'Gemfile*' \) -print \
  | tee "$OLDPWD/evidence/artifacts/manifests.txt"

# Direct dependencies (npm example):
jq -r '.dependencies // {} | to_entries[] | "\(.key) \(.value)"' package.json
# Python example:
grep -vE '^\s*(#|$)' requirements*.txt
```

Write the flat list to `evidence/artifacts/deps.txt`: one `ecosystem name
version-spec` per line.

## 2. Manifest checks (offline, provable)

For each dependency, record in `deps.txt` whether:

- **The version spec is floating.** `*`, `latest`, `^x`, `~x`, a range, a git
  URL without a commit hash. Exact pins (`1.2.3`, `==1.2.3`, `v1.2.3` tag is
  still mutable, a full sha256 is not) are pinned.
- **A lockfile exists.** `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml`,
  `Pipfile.lock`/`poetry.lock`/`uv.lock`/`requirements.txt` with `==`,
  `go.sum`, `Cargo.lock`, `Gemfile.lock`. No lockfile = finding.
- **Install scripts are declared.** In `package.json` or a vendored
  `node_modules/<pkg>/package.json`: `preinstall`, `install`, `postinstall`
  under `scripts`. Save the excerpt:

```bash
jq '{name, version, scripts}' /home/agent/target/node_modules/<pkg>/package.json \
  > evidence/artifacts/install-script-<pkg>.json
```

## 3. Registry metadata per dependency

Registry documents are megabytes: keep the extract a reviewer needs.

```bash
# npm (scoped names: @scope/name -> @scope%2fname)
curl -fsSL "https://registry.npmjs.org/<pkg>" | jq '{
  name, created: .time.created, modified: .time.modified,
  latest: ."dist-tags".latest,
  maintainers: [.maintainers[]?.name],
  repository: .repository.url,
  install_scripts: [.versions[."dist-tags".latest].scripts
    | keys? // [] | .[] | select(. == "preinstall" or . == "install" or . == "postinstall")]
}' > "evidence/artifacts/registry-<pkg>.json"
# HTTP 404 = the name has no public package: a lead, write the status to
# artifacts/registry-<pkg>.txt instead.

# PyPI
curl -fsSL "https://pypi.org/pypi/<pkg>/json" | jq '{
  name: .info.name, author: .info.author,
  repository: (.info.project_urls.Source // .info.home_page),
  latest: .info.version,
  wheel: ([.releases[.info.version][]?.packagetype] | contains(["bdist_wheel"])),
  install_scripts: "wheel installs run no code; an sdist-only package may run setup.py at build time"
}' > "evidence/artifacts/registry-<pkg>.json"
```

Signals to weigh: single maintainer, long dormancy, placeholder versions
(`0.0.0`), no repository link, publish days before the target pinned it.

## 4. OpenSSF Scorecard on resolvable repositories

```bash
# The package flag resolves the package's declared repository, then runs
# the checks on it.
# TODO(verify): which ecosystems the package flags support beyond GitHub
# repositories is unverified without a live run.
scorecard --npm=<pkg> --format=json --show-details \
  -o "evidence/artifacts/scorecard-<pkg>.json"
scorecard --pypi=<pkg> --format=json --show-details \
  -o "evidence/artifacts/scorecard-<pkg>.json"
# Or straight on the repository the registry metadata gave:
scorecard --repo=github.com/<owner>/<repo> --format=json --show-details \
  -o "evidence/artifacts/scorecard-<pkg>.json"
```

- Read `.checks[]`: `Maintained`, `Security-Policy`, `Dangerous-Workflow`,
  `Packaging`, `Pinned-Dependencies`, `License`, `Vulnerabilities`. A score
  below 5 is a weak signal; quote it in the risk table, it is not alone a
  finding.
- `could not detect the project repository` or rate-limit errors: record the
  exit code in `tools_run` and file a hypothesis.

## 5. Known advisories

```bash
# --no-resolve: transitive resolution needs hosts outside the allow-list
# (deps.dev); the planted advisories are direct dependencies.
osv-scanner scan source -r /home/agent/target --no-resolve --format json \
  --output-file evidence/artifacts/osv.json
```

osv-scanner scans lockfiles and manifests it finds (`requirements.txt`,
`go.mod`, `Cargo.lock`, SBOMs). A bare `package.json` without a lockfile is
not a source: record that as part of the missing-lockfile evidence. Exit
code 1 means advisories were found, not that the tool failed.

## 6. Look-alike names

For each dependency name, compare against the well-known packages of its
ecosystem (`express`, `lodash`, `requests`, `pyyaml`, `urllib3`, ...):

- edit distance 1-2: inserted, dropped, swapped or doubled characters
  (`expresss`, `reqeusts`), separator changes (`python-requests` for
  `requests`), confusables (`0`/`o`, `1`/`l`, `rn`/`m`).
- A match is only a lead. A typosquat is proven when registry data shows
  hostile behaviour (obfuscated install scripts, code that differs from the
  repo, maintainer history of similar names). Without that proof it is a
  `hypothesis` with the name, the look-alike target and the registry facts
  you collected.

## 7. Risk table and evidence

Write `evidence/artifacts/risk-table.md`, one row per dependency:

`| package | ecosystem | spec | pinned | install script | repo | scorecard | advisories | verdict |`

Then the findings:

- `rule: install-script` — a dependency runs code at install time
  (`preinstall`/`install`/`postinstall` in package.json `scripts`; a
  PyPI package that ships only an sdist is a hypothesis: modern pip still
  builds it, wheel installs run nothing).
- `rule: unpinned-dependency` — floating spec or missing lockfile.
- `rule: <advisory id>` (for example `GHSA-8q59-q68h-6hv4`) — an
  osv-scanner entry with a fixed version you can name in the remediation.
- `rule: unmaintained-repository` — Scorecard `Maintained` 0 plus a registry
  `modified` date older than two years.

## Pitfalls

- Reporting a look-alike name as a finding. It is a hypothesis until
  registry or repository data proves hostile behaviour.
- Treating osv-scanner exit code 1 or a scorecard "no repository" error as a
  tool failure. Record them; they are data.
- Recommending `npm install` or `pip install` "to check". You never run a
  dependency's install.
- Rating the aggregate scorecard score as a finding on its own. Quote the
  check scores; a low aggregate needs a named, provable reason.
