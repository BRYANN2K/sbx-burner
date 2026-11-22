---
name: gate
category: devsecops
summary: Run secrets, SCA, SAST, IaC and licence checks on a codebase, merge every report into one SARIF and decide pass or fail from a read-only policy file.
risk: low
time: 45m
tested_with: [codex]
variants:
  linux: beta
  macos: planned
status: beta
licence: Apache-2.0
sources:
  - https://github.com/gitleaks/gitleaks
  - https://github.com/google/osv-scanner
  - https://semgrep.dev/docs/
  - https://aquasecurity.github.io/trivy/
  - https://github.com/anchore/syft
---

# gate

The agent runs the pull-request security checks on a mounted codebase —
secrets, SCA, SAST, IaC and licence — merges every report into a single
`gate.sarif`, and decides pass or fail strictly from
`fixtures/gate-policy.yaml`. A check that fails to run fails the gate.

## When to use it

- To replicate "the CI gate" locally before opening a pull request.
- To tune a gate policy against a repository: edit your copy of
  `gate-policy.yaml`, run, read the decision.
- As the umbrella over the wave-1 scanner recipes (secrets-scan, sca-osv,
  sast-semgrep, iac-scan, container-scan, sbom-sign, licence-compliance).

## What you get

- `report.md` and `report.json` in `runs/<timestamp>-gate/`.
- `artifacts/gate.sarif`: every scanner merged, one SARIF run per tool.
- `artifacts/pr-summary.md`: the table to paste on the pull request.
- `artifacts/gate-result.json`: counts per check, blocking items, reasons.
- One raw report per check (`gitleaks.json`, `osv.json`, `semgrep.json`,
  `trivy-config.json`, `trivy-image.json` when an image was scanned,
  `sbom.cdx.json`).

## Run

```console
$ python -m lab run devsecops/gate --dry-run
$ python -m lab run devsecops/gate --target ./my-repo
$ python -m lab run devsecops/gate --target-repo owner/my-repo@main
```

The target is a local folder (`--target PATH`) or a git repository
(`--target-repo SRC[@REF]`: `owner/repo`, an https or ssh URL). The runner
clones a repository on the host with your own git login, so private
repositories work and no credential enters the sandbox. Either way it is
mounted read-only at `/home/agent/target`. The container check
runs only when the target has a Dockerfile; `gate.py` marks it required then.

## Evidence

| Artifact | Content |
| --- | --- |
| `artifacts/gate.sarif` | Merged SARIF 2.1.0, one run per scanner |
| `artifacts/pr-summary.md` | Gate decision table for the pull request |
| `artifacts/gate-result.json` | Per-check counts, blocking items, policy hash |
| `artifacts/<check>.json` / `.sarif` | Raw output of each scanner |

## Safety

- The policy file is read-only during a run: the agent reports the decision,
  it never edits the policy, weakens a rule or skips a check to pass.
- A missing or unreadable report for a required check fails the gate —
  silence is never a pass.
- Scans run inside the sandbox; the only egress is the tool downloads and
  the OSV/trivy data hosts on the allow-list.

## Variants

- Linux: Docker's built-in Debian agent plus `kits/devsecops`, which bakes
  gitleaks, osv-scanner, syft and trivy; `tools/install.sh` adds semgrep.
- macOS: planned, through macsbx.

## Licences

| Tool | Licence | How it is used |
| --- | --- | --- |
| gitleaks 8.30.1 | MIT | baked in `kits/devsecops` |
| osv-scanner 2.7.1 | Apache-2.0 | baked in `kits/devsecops` |
| syft 1.57.2 | Apache-2.0 | baked in `kits/devsecops` |
| trivy 0.76.2 | Apache-2.0 | baked in `kits/devsecops` |
| semgrep 1.186.0 | LGPL-2.1 | `lab_pipx` at run time, executed only |
