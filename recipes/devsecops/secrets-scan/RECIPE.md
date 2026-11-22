---
name: secrets-scan
category: devsecops
summary: Scan a repository and its git history for leaked credentials with gitleaks, then triage every hit before reporting.
risk: low
time: 10m
tested_with: [codex, claude]
variants:
  linux: beta
  macos: planned
status: beta
licence: Apache-2.0
sources:
  - https://github.com/gitleaks/gitleaks
  - https://github.com/trufflesecurity/trufflehog
---

# secrets-scan

The agent scans a repository (working tree and full git history) for leaked
credentials, removes false positives, and reports each real leak with the
commit that introduced it and a rotation plan. Secrets are masked everywhere.

## When to use it

- Before making a repository public.
- As a gate on pull requests (see `devsecops/gate`).
- After an incident, to find what else leaked.

## What you get

- `report.md` and `report.json` in `runs/<timestamp>-secrets-scan/`.
- One finding per leaked credential, with file, line, commit and rule.
- False positives listed as hypotheses with the reason they were dismissed.

## Run

```console
$ python -m lab run devsecops/secrets-scan --target ./my-repo --dry-run
$ python -m lab run devsecops/secrets-scan --target ./my-repo
$ python -m lab run devsecops/secrets-scan --target-repo owner/my-repo@main
```

The target is a local folder (`--target PATH`) or a git repository
(`--target-repo SRC[@REF]`: `owner/repo`, an https or ssh URL). The runner
clones a repository on the host with your own git login, so private
repositories work and no credential enters the sandbox. Either way it is
mounted read-only at `/home/agent/target`. No scope file is
needed: the recipe contacts no target host.

## Evidence

| Artifact | Content |
| --- | --- |
| `artifacts/gitleaks.json` | Raw gitleaks report, secrets redacted by gitleaks (`--redact`) |
| `artifacts/gitleaks.sarif` | The same report as SARIF, for code scanning |
| `artifacts/trufflehog.jsonl` | Optional second opinion, unverified mode |

## Safety

- The agent never tests whether a credential is live. trufflehog runs with
  `--no-verification`, so no leaked key is ever sent to a third party.
- Secrets are never written in clear text: gitleaks redacts, the agent masks,
  and the runner redacts the report again.

## Variants

- Linux: Docker's built-in Debian agent with the `kits/devsecops` toolbox.
- macOS: planned, through macsbx.

## Licences

| Tool | Licence | How it is used |
| --- | --- | --- |
| gitleaks 8.30.1 | MIT | Baked into `kits/devsecops`, or installed by `tools/install.sh` |
| trufflehog 3.100.0 | AGPL-3.0 | Downloaded and run at run time only; never vendored or linked |
