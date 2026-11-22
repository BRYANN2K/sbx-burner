---
name: supply-chain-risk
category: devsecops
summary: Assess a project's third-party dependencies for supply-chain risk: install scripts, floating versions, look-alike names, registry health and OpenSSF Scorecard.
risk: low
time: 15m
tested_with: [codex]
variants:
  linux: beta
  macos: planned
status: beta
licence: Apache-2.0
sources:
  - https://github.com/ossf/scorecard
  - https://github.com/google/osv-scanner
  - https://github.com/trailofbits/skills
---

# supply-chain-risk

The agent inventories the dependencies of the repository mounted at
`/home/agent/target`, then rates each one: does it run code at install time,
is the version pinned, does its name look like a typosquat of a popular
package, what does its registry metadata say, and how does its source
repository score on OpenSSF Scorecard. Suspicions without registry or
repository proof are reported as hypotheses, not findings.

## When to use it

- Before adding or upgrading a dependency.
- To audit the dependency surface of a codebase you inherit.
- As a periodic review of a project's supply-chain exposure.

## What you get

- `report.md` and `report.json` in `runs/<timestamp>-supply-chain-risk/`.
- One finding per proven risk (install script, unpinned version, missing
  lockfile, published advisory), one hypothesis per unproven suspicion.
- A per-dependency risk table as `artifacts/risk-table.md`.

## Run

```console
$ python -m lab run devsecops/supply-chain-risk --target ./my-repo --dry-run
$ python -m lab run devsecops/supply-chain-risk --target ./my-repo
$ python -m lab run devsecops/supply-chain-risk --target-repo owner/my-repo@main
```

The target is a local folder (`--target PATH`) or a git repository
(`--target-repo SRC[@REF]`: `owner/repo`, an https or ssh URL). The runner
clones a repository on the host with your own git login, so private
repositories work and no credential enters the sandbox. Either way it is
mounted read-only at `/home/agent/target`. No scope file is
needed: the recipe only contacts the npm and PyPI registries, the OSV API,
and `api.github.com` plus `codeload.github.com` for Scorecard.

Without a stored GitHub credential the agent queries the GitHub API
unauthenticated and can hit the rate limit. Run `sbx secret set github` once
on the host to let the sandbox proxy authenticate those requests; the token
never enters the sandbox.

<!-- TODO(verify): whether the proxy injects the token into requests from a
non-agent tool like scorecard is unverified without a live run. -->

## Evidence

| Artifact | Content |
| --- | --- |
| `artifacts/registry-<pkg>.json` | Raw npm or PyPI registry metadata per dependency |
| `artifacts/scorecard-<pkg>.json` | OpenSSF Scorecard JSON for each resolvable repository |
| `artifacts/osv.json` | osv-scanner results for the target's lockfiles and manifests |
| `artifacts/risk-table.md` | One row per dependency: pinned, install script, repo score, advisories |

## Safety

- The agent reads the target and queries public registries and APIs only; it
  never installs, executes or deploys a dependency.
- A package that merely looks like a typosquat is never installed or probed
  beyond public registry metadata.
- The GitHub token stays on the host: `sbx secret set github` lets the
  sandbox proxy inject it into `api.github.com` requests.
  <!-- TODO(verify): proxy injection for non-agent tools, unverified. -->

## Variants

- Linux: Docker's built-in Debian agent with the `kits/devsecops` toolbox,
  plus OpenSSF Scorecard and `jq` installed by `tools/install.sh`.
- macOS: planned, through macsbx.

## Licences

| Tool | Licence | How it is used |
| --- | --- | --- |
| OpenSSF Scorecard 5.7.0 | Apache-2.0 | Downloaded at run time, checksum-verified |
| osv-scanner 2.7.1 | Apache-2.0 | Baked into `kits/devsecops`, or installed by `tools/install.sh` |
| jq | MIT | Installed from the Debian distribution by `tools/install.sh` |

The `trailofbits/skills` repository (CC BY-SA) is linked as further reading
on dependency risk review; nothing from it is copied here.
