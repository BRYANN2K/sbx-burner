---
name: sca-osv
category: devsecops
summary: Scan a project's lockfiles and manifests for known dependency vulnerabilities with osv-scanner, then report one finding per advisory group.
risk: low
time: 10m
tested_with: [codex]
variants:
  linux: beta
  macos: planned
status: beta
licence: Apache-2.0
sources:
  - https://github.com/google/osv-scanner
  - https://osv.dev/
---

# sca-osv

The agent scans a project's dependency lockfiles and manifests with
osv-scanner against the OSV database, groups the matching advisories, and
reports each vulnerable package once per advisory group with the version
that fixes it.

## When to use it

- Before a release, to list the vulnerabilities the dependencies carry.
- When taking over a repository you did not write.
- As the dependency step of `devsecops/gate`.

## What you get

- `report.md` and `report.json` in `runs/<timestamp>-sca-osv/`.
- One finding per vulnerable package and advisory group, with the GHSA or
  CVE id, the CVSS vector, and the lowest fixed version.
- Advisory groups the agent could not assess, listed as hypotheses.

## Run

```console
$ python -m lab run devsecops/sca-osv --target ./my-project --dry-run
$ python -m lab run devsecops/sca-osv --target ./my-project
$ python -m lab run devsecops/sca-osv --target-repo owner/my-repo@main
```

The target is a local folder (`--target PATH`) or a git repository
(`--target-repo SRC[@REF]`: `owner/repo`, an https or ssh URL). The runner
clones a repository on the host with your own git login, so private
repositories work and no credential enters the sandbox. Either way it is
mounted read-only at `/home/agent/target`. No scope file is
needed: the recipe reads files and contacts no target host.

To try it on a planted target:

```console
$ bash recipes/devsecops/sca-osv/evals/make-target.sh /tmp/osv-demo
$ python -m lab run devsecops/sca-osv --target /tmp/osv-demo
$ python -m lab eval devsecops/sca-osv --run runs/<id>
```

## Evidence

| Artifact | Content |
| --- | --- |
| `artifacts/osv.json` | Raw osv-scanner report |
| `artifacts/osv.sarif` | The same report as SARIF, for code scanning |

## Safety

- Static analysis only: the agent never installs, builds or runs the
  target's code or its package manager.
- The only data that leaves the sandbox is the dependency list: package
  names, versions and ecosystems go to `api.osv.dev` for advisory matching.
- The scan is read-only against the OSV database; no file content is sent.

## Variants

- Linux: Docker's built-in Debian agent with the `kits/devsecops` toolbox.
- macOS: planned, through macsbx.

## Licences

| Tool | Licence | How it is used |
| --- | --- | --- |
| osv-scanner 2.7.1 | Apache-2.0 | Baked into `kits/devsecops`, or installed by `tools/install.sh` |
