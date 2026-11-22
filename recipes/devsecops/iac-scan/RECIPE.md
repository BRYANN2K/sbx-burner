---
name: iac-scan
category: devsecops
summary: Scan Terraform, Kubernetes manifests and Dockerfiles for misconfigurations with trivy, then split real exposure from hygiene.
risk: low
time: 15m
tested_with: [codex]
variants:
  linux: beta
  macos: planned
status: beta
licence: Apache-2.0
sources:
  - https://github.com/aquasecurity/trivy
  - https://trivy.dev/latest/docs/scanner/misconfiguration/
  - https://github.com/bridgecrewio/checkov
---

# iac-scan

The agent scans infrastructure-as-code files (Terraform, Kubernetes manifests,
Dockerfiles) for misconfigurations. It then reads each flagged resource and
decides: is this an exposure someone can use, or a hygiene item? Scanners
report dozens of hits per file; the report keeps the few that matter on top.

## When to use it

- Before merging a change to Terraform, Helm output or manifests.
- When taking over an infrastructure repository you did not write.
- As the IaC step of `devsecops/gate`.

## What you get

- `report.md` and `report.json` in `runs/<timestamp>-iac-scan/`.
- One finding per root cause, with tool, rule ID, `file:line`, severity and
  the exact change that fixes it.
- Exposures and hygiene items counted separately in `metrics`.
- Hits that depend on context the repository does not show (account-level
  controls, admission policies) listed as hypotheses.

## Run

```console
$ python -m lab run devsecops/iac-scan --target ./infra --dry-run
$ python -m lab run devsecops/iac-scan --target ./infra
$ python -m lab run devsecops/iac-scan --target-repo owner/my-repo@main
```

The target is a local folder (`--target PATH`) or a git repository
(`--target-repo SRC[@REF]`: `owner/repo`, an https or ssh URL). The runner
clones a repository on the host with your own git login, so private
repositories work and no credential enters the sandbox. Either way it is
mounted read-only at `/home/agent/target`. No scope file is
needed: the recipe reads files and contacts no target host.

To try it on a planted target:

```console
$ bash recipes/devsecops/iac-scan/evals/make-target.sh /tmp/iac-demo
$ python -m lab run devsecops/iac-scan --target /tmp/iac-demo
$ python -m lab eval devsecops/iac-scan --run runs/<id>
```

## Evidence

| Artifact | Content |
| --- | --- |
| `artifacts/trivy-config.json` | Raw `trivy config` report |
| `artifacts/trivy-config.sarif` | The same report as SARIF, for code scanning |
| `artifacts/checkov/results_json.json` | Optional checkov report |
| `artifacts/checkov/results_sarif.sarif` | Optional checkov report as SARIF |

## Safety

- Static analysis only. The agent never runs `terraform plan` or `apply`,
  never runs `kubectl` against a cluster and never builds the Dockerfiles.
- No cloud credentials are needed or used. If the target contains some, the
  agent does not use them (run `devsecops/secrets-scan` for those).
- The scans are offline: no file content leaves the sandbox.

## Variants

- Linux: Docker's built-in Debian agent with the `kits/devsecops` toolbox.
- macOS: planned, through macsbx.

## Licences

| Tool | Licence | How it is used |
| --- | --- | --- |
| trivy 0.76.2 | Apache-2.0 | Baked into `kits/devsecops`, or installed by `tools/install.sh` |
| checkov 3.4.6 | Apache-2.0 | Optional, installed with pipx at run time |
