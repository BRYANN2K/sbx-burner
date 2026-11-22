---
name: container-scan
category: devsecops
summary: Scan the user's container image — a Dockerfile context or an image ref/tarball — with trivy and grype, then reconcile and rank fixes.
risk: low
time: 30m
variants:
  linux: beta
  macos: planned
status: beta
licence: Apache-2.0
sources:
  - https://github.com/aquasecurity/trivy
  - https://github.com/anchore/grype
---

# container-scan

One image, two scanners, one triaged answer. The recipe scans the user's
container image inside the sandbox — built from their Dockerfile context,
or pulled/loaded from their ref or tarball — runs trivy and grype against
it, and merges the two reports into a single per-(CVE, package) list with
per-scanner severities and fix versions. Findings are the union's high and
critical CVEs; metrics count what each scanner saw alone.

Two scanners are worth it because their databases disagree: NVD entries vs
distro trackers cover different packages and rate the same CVE differently.
The reconciled report keeps both voices instead of silently picking one.

## Usage

The recipe needs a target (`run.target: required`); three kinds are accepted:

```bash
# path: a Dockerfile build context, mounted read-only at /home/agent/target
python -m lab run devsecops/container-scan --target /path/to/project

# repo: a Dockerfile context in a git repo, cloned on the host with your own
# git login (private repos too) and mounted read-only like a path
python -m lab run devsecops/container-scan --target-repo owner/repo@main

# image: a local or registry ref — resolved on the host (local Docker first,
# then a pull with your docker login) and loaded inside the sandbox
python -m lab run devsecops/container-scan --target-image debian:bookworm-slim

# image: a docker save tarball — the runner loads it inside the sandbox
python -m lab run devsecops/container-scan --target-image ./image.tar
```

For `path` and `repo` the agent builds the context's `Dockerfile` and scans the built
tag (a tarball inside the directory or a plain tree get a load or a
filesystem scan). For `image` the runner resolves the ref on the
host (or takes the tarball), loads it into the sandbox Docker engine and
records its digest; registry credentials never enter the sandbox. The
agent then scans `$LAB_TARGET_IMAGE` directly. No `--demo`: the
bundled `evals/make-target.sh` generates a throwaway context on an
end-of-life base image for the eval and for local dry runs only.

## What you get

- `artifacts/trivy.json`, `artifacts/grype.json` — raw scanner output.
- `artifacts/reconciled.json` — one row per unique `(cve, package)`:
  scanners that saw it, each severity, each fix version, union severity,
  plus `counts` (`total`, `fixable`, `only_trivy`, `only_grype`,
  `by_union_severity`).
- Findings: one per CVE at union high/critical, CVSS vector when the
  report carries one, fix or "rebuild on a supported base" as remediation.
- `artifacts/docker-build.txt` — the build log.

## Safety and limits

- The image is **built and scanned, never run, never pushed**. The only
  registry traffic at run time is the Dockerfile's own `FROM` pull; both
  vulnerability databases are prefetched while install hosts are open.
- `docker build` executes the target Dockerfile's `RUN` steps inside the
  sandbox's Docker Engine — the recipe builds what it scans.
- Scanners read package metadata; they do not execute the image. A
  vulnerable library that is installed but never loaded still reports.
- Severity is advisory: scanners disagree legitimately, and a CVSS score
  says nothing about whether the code path is reachable.
- Vulnerability databases are large downloads on first use; the 30-minute
  budget covers a cold cache.

## Licences

| Component | Licence | How it is used |
| --- | --- | --- |
| trivy 0.76.2 | Apache-2.0 | Scanner, run inside the sandbox |
| grype 0.122.1 | Apache-2.0 | Scanner, run inside the sandbox |
| reconcile.py | Apache-2.0 | Recipe's own merge script |

Vulnerability database contents are the scanners' upstream data feeds;
reports cite the scanner, not the recipe.
