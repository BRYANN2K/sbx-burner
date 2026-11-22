---
name: pr-gate
description: Run the seven gate checks (secrets, SCA, SAST, IaC, container when a Dockerfile exists, SBOM and licence), merge reports into one SARIF and apply the read-only policy. Use when running devsecops/gate or replicating a CI security gate.
---

# Pull-request security gate

Order matters: run every scanner first (each writes one JSON and one SARIF),
then let `fixtures/gate.py` decide. Never touch `fixtures/gate-policy.yaml`.

`T=/home/agent/target`, `A=evidence/artifacts` throughout.

## 1. Secrets — gitleaks

```bash
gitleaks dir "$T" --report-path "$A/gitleaks.json" --report-format json --redact
gitleaks dir "$T" --report-path "$A/gitleaks.sarif" --report-format sarif --redact
# exit 1 = leaks found: a result, not an error.
```

`gitleaks dir` scans the working tree only — secrets committed and later
removed stay in Git history. Report that scope in the finding when it
matters; scanning history needs `gitleaks git` and is not part of this gate.

## 2. SCA — osv-scanner

```bash
osv-scanner scan --recursive "$T" --format json  > "$A/osv.json"
osv-scanner scan --recursive "$T" --format sarif > "$A/osv.sarif"
# exit 1 = vulnerabilities found.
```

## 3. SAST — semgrep

```bash
# The bundled rules cover the baseline; add the target's own .semgrep.yml
# as a second --config when it exists.
semgrep scan --metrics=off --config fixtures/semgrep-rules.yaml --json -o "$A/semgrep.json" "$T"
semgrep scan --metrics=off --config fixtures/semgrep-rules.yaml --sarif -o "$A/semgrep.sarif" "$T"
```

## 4. IaC — trivy config

```bash
# --skip-check-update: the checks bundle is prefetched at install time.
trivy config "$T" --skip-check-update --format json  -o "$A/trivy-config.json"
trivy config "$T" --skip-check-update --format sarif -o "$A/trivy-config.sarif"
```

## 5. Container — trivy image (only when a Dockerfile exists)

```bash
# Sandbox ships a private Docker Engine; build, then scan the image.
# --skip-db-update --skip-java-db-update: both indexes are prefetched at
# install time, so no trivy host is needed during the run.
find "$T" -name 'Dockerfile*' -o -name '*.dockerfile'
docker build -q -t gate-target "$T"
trivy image gate-target --skip-db-update --skip-java-db-update --format json  -o "$A/trivy-image.json"
trivy image gate-target --skip-db-update --skip-java-db-update --format sarif -o "$A/trivy-image.sarif"
```

Warning: `docker build` executes the target's `RUN` steps inside the
sandbox's Docker Engine. A hostile Dockerfile runs code during the build —
that is contained by the sandbox, but record it: the gate builds what it
scans.

## 6. SBOM — syft (doubles as the licence source)

```bash
syft "dir:$T" -o "cyclonedx-json=$A/sbom.cdx.json"
```

## 7. Decide — gate.py

```bash
python3 fixtures/gate.py --artifacts "$A" \
  --policy fixtures/gate-policy.yaml --target "$T"
# exit 0 = gate passed, 1 = failed, 2 = bad input.
```

It writes `gate.sarif` (one run per tool), `gate-result.json` (counts,
blocking items, reasons, policy sha256) and `pr-summary.md`. Read the
decision and reasons from `gate-result.json`, not from memory.

## A check that failed to run

Record the command and error in `tools_run`, leave the report file absent,
and continue with the next check. `gate.py` marks a missing required report
as a gate failure — that is the designed behaviour, never compensate by
hand-writing a report.

## Pitfalls

- Editing the policy, the rules or a report so the gate passes. Forbidden;
  the gate exists to fail.
- Skipping a scanner because "the target has no such files". Run it anyway;
  an empty report is a pass, a missing report is a fail.
- Counting scanner findings as gate failures. Only items the policy marks
  blocking count — a low-severity list is information, not a veto.
- Reporting the decision from the exit code alone. Quote `gate-result.json`.
