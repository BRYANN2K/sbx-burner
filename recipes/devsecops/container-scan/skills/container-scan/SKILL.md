---
name: container-scan
description: Build or load a container image inside the sandbox, scan it with trivy and grype, reconcile the two reports by CVE+package and rank fixes. Use when asked to audit a Docker image, find CVEs in a container, compare scanner results or list fixable vulnerabilities.
---

# Container image scan

## 1. Find the image to scan

`LAB_TARGET_KIND` picks the flow:

```bash
A="$PWD/evidence/artifacts"
mkdir -p "$A"

# image: the runner already pulled the registry ref (or docker-loaded the
# tarball) into the sandbox's Docker engine. Scan it as-is: no build, no pull.
if [ "$LAB_TARGET_KIND" = image ]; then
  IMG="$LAB_TARGET_IMAGE"
  if [ "${IMG#tarball:}" != "$IMG" ]; then
    # A docker save tarball was loaded; the runner saved its reference.
    IMG="$(cat .lab/target-image-ref)"
  fi

# path or repo (cloned on the host): the user's files are read-only at
# $LAB_TARGET_PATH — a build context.
elif [ "$LAB_TARGET_KIND" = path ] || [ "$LAB_TARGET_KIND" = repo ]; then
  docker build -t lab-scan-target:latest "$LAB_TARGET_PATH" > "$A/docker-build.txt" 2>&1
  echo "build exit: $?"
  IMG=lab-scan-target:latest
  # A path may instead ship a ready-made tarball:
  # docker load -i "$LAB_TARGET_PATH/image.tar" >> "$A/docker-build.txt" 2>&1
  # IMG="$(docker image ls --format '{{.Repository}}:{{.Tag}}' | grep -v '<none>' | head -n 1)"
fi
```

The sandbox has its own Docker daemon; builds and pulls stay inside it. A
`path` or `repo` target with neither a Dockerfile nor a tarball gets a filesystem
scan instead (step 2, fallback).

## 2. Scan with both scanners

```bash
trivy image --scanners vuln --skip-version-check --skip-db-update \
  --format json --output "$A/trivy.json" "$IMG"
echo "trivy exit: $?"

GRYPE_CHECK_FOR_APP_UPDATE=false GRYPE_DB_AUTO_UPDATE=false \
  grype "docker:$IMG" -o json --file "$A/grype.json"
echo "grype exit: $?"
```

Both vulnerability databases are prefetched while install hosts are open,
so the scanners run offline: `--skip-db-update` keeps trivy on the cached
`trivy-db`/`trivy-java-db` and `GRYPE_DB_AUTO_UPDATE=false` keeps grype on
its cached database. `GRYPE_CHECK_FOR_APP_UPDATE=false` keeps grype off its
update-check host too. A database the install step failed to fetch is a
stop-condition error, not something to work around with stale flags.

For a tarball you loaded yourself (or cannot load), scan the archive
directly: `trivy image --scanners vuln --skip-db-update --input image.tar`
and `GRYPE_DB_AUTO_UPDATE=false grype docker-archive:image.tar`.

Fallback, a `path` or `repo` target with no image material at all:

```bash
trivy fs --scanners vuln --skip-version-check --skip-db-update \
  --format json --output "$A/trivy.json" "$LAB_TARGET_PATH"
GRYPE_DB_AUTO_UPDATE=false grype "dir:$LAB_TARGET_PATH" -o json --file "$A/grype.json"
```

## 3. Reconcile by CVE and package

```bash
python3 fixtures/reconcile.py \
  --trivy "$A/trivy.json" --grype "$A/grype.json" \
  --out "$A/reconciled.json"          # prints the counts as one JSON line

jq '.counts' "$A/reconciled.json"
jq -r '.pairs[] | select(.union_severity=="critical" or .union_severity=="high")
  | [.cve, .package, (.scanners|join("+")), .union_severity, (.fixed_versions|join(","))]
  | @tsv' "$A/reconciled.json"
```

A pair is `(cve, package)`. `union_severity` is the higher of the two
scanners' ratings; scanners disagree legitimately (different namespaces:
NVD vs the distro tracker).

## 4. Triage

- **Fixable first.** `fixed_versions` non-empty beats a higher score with no
  fix: say the upgrade in remediation.
- **One finding per CVE**, however many binary packages it hits (same
  source package, same root cause). List the packages in `location`.
- **Divergence is signal.** A critical/high pair seen by only one scanner
  (`only_trivy`, `only_grype`) still counts — the union is the report. Note
  big divergences in the summary and as a hypothesis.
- **Severity wording.** With a CVSS 3.1 vector, `cvss` goes in the finding
  and the band sets the severity; without one, use the union severity.
- `wont-fix` / no versions on an EOL distro is not "no problem": it means
  the fix is a newer base image.

## 5. Report

- `metrics` comes from `reconciled.json` `.counts`: `total`, `fixable`,
  `only_trivy`, `only_grype`.
- The summary names the image tag, the package/fixable picture, the
  divergence and what was not scanned (e.g. no Java DB, OS packages only).

## Pitfalls

- Scanning the base image name instead of the tag you just built: you would
  audit upstream, not the target.
- Filtering by severity in the scan (`--severity HIGH`) — keep the full
  report; `reconciled.json` needs the low/medium rows for divergence stats.
- Treating "grype saw it, trivy did not" as a false positive by default:
  databases have different coverage. It is a finding with one witness.
- `docker run` to "check" something. Scan only; the image never starts.
