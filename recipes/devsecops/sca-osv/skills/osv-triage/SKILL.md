---
name: osv-triage
description: Scan dependency lockfiles and manifests for known vulnerabilities with osv-scanner, then triage each advisory group into one finding. Use when asked to check dependencies, lockfiles or packages for CVEs or vulnerable versions.
---

# Dependency scan and triage

## 1. Scan

```bash
A="$PWD/evidence/artifacts"
mkdir -p "$A"
cd /home/agent/target

# --data-source native + --no-resolve: the only network call is the
# advisory query to api.osv.dev; packages are reported exactly as pinned.
osv-scanner scan source -r --data-source native --no-resolve \
  --format json --output-file "$A/osv.json" . 2> "$A/osv.stderr.txt"
echo "osv-scanner exit: $?"   # 0 = clean, 1 = advisories found, other = error

# Same scan as SARIF for code scanning.
osv-scanner scan source -r --data-source native --no-resolve \
  --format sarif --output-file "$A/osv.sarif" . 2>> "$A/osv.stderr.txt"
```

## 2. Read the report

One line per advisory group, to plan the triage:

```bash
jq -r '.results[] | .source.path as $f | .packages[]
  | .package as $p | .groups[]
  | [$f, $p.name, $p.version, (.ids | join(",")), .max_severity] | @tsv' \
  "$A/osv.json"
```

For one advisory, the lowest fixed version and the CVSS v3 vector:

```bash
jq -r '.results[].packages[] | .package.name as $n | .vulnerabilities[]
  | select(.id == "GHSA-XXXX-XXXX-XXXX")
  | [$n,
     ([.affected[].ranges[] | select(.type=="ECOSYSTEM") | .events[] | .fixed // empty]
        | sort_by(split(".") | map(tonumber? // 0)) | first // "none"),
     ([.severity[]? | select(.type=="CVSS_V3") | .score] | first // "none")]
  | @tsv' "$A/osv.json"
```

`groups` is the deduplicated view: one entry per advisory even though the
same advisory appears once per alias (`GHSA-*`, `PYSEC-*`, `CVE-*`) in
`vulnerabilities`. Report per group, not per entry.

## 3. Triage each group

1. **Which alias is the rule?** The GHSA id when the group has one, else
   the CVE id, else the group's first id.
2. **What is the severity?** A CVSS v3 vector goes in `cvss` with its
   base score; the gate recomputes both. `groups[].max_severity` mixes
   CVSS v4 scores the gate does not validate: without a v3 vector, apply
   the severity rubric in AGENTS.md and say which score you used.
3. **What fixes it?** The lowest `fixed` event in the ECOSYSTEM ranges.
   `introduced`/`last_affected` boundaries go in the description.
4. **Is the vulnerable code reachable?** Only downgrade or dismiss when a
   code reference proves it (`file:line` showing the function or import
   is never used). A lockfile-only scan cannot prove reachability.

## Pitfalls

- Reporting one finding per `vulnerabilities` entry. The same advisory
  repeats under each alias; use `groups`.
- Citing `max_severity` as the CVSS score. It is the maximum across
  aliases and versions, often a v4 score; cite a v3 vector instead.
- Dropping `--no-resolve` or `--data-source native`: transitive
  resolution then calls deps.dev or ecosystem registries, which are not
  in the allow-list. The scan fails; keep the flags.
- Treating exit code 1 as a tool failure. It means advisories were found.
- Upgrading advice like "just bump to latest". Give the lowest fixed
  version; the latest major may break the API.
