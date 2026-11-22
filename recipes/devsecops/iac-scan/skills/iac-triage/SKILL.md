---
name: iac-triage
description: Scan Terraform, Kubernetes manifests and Dockerfiles for misconfigurations with trivy config (and optionally checkov), then triage each hit as exploitable exposure or hygiene. Use when asked to review IaC, infrastructure code, manifests, Helm output or Dockerfiles for security problems.
---

# IaC scan and triage

## 1. Scan

```bash
A="$PWD/evidence/artifacts"
mkdir -p "$A"
cd /home/agent/target

# Offline: --skip-check-update makes trivy use the checks embedded in
# the binary (verified on 0.76.2: it falls back with a log line, no download).
# TODO(verify): --disable-telemetry on trivy 0.76.2 (flag seen on 0.72.0).
trivy config --skip-check-update --skip-version-check --disable-telemetry \
  --format json --output "$A/trivy-config.json" . 2> "$A/trivy-config.stderr.txt"
echo "trivy exit: $?"   # 0 unless the scan itself failed

# Same scan as SARIF for code scanning.
trivy config --skip-check-update --skip-version-check --disable-telemetry \
  --format sarif --output "$A/trivy-config.sarif" . 2>> "$A/trivy-config.stderr.txt"
```

One line per hit, to plan the triage:

```bash
jq -r '.Results[]? | .Target as $t | .Misconfigurations[]?
  | [$t, (.CauseMetadata.StartLine // 0), .ID, .Severity, .Title] | @tsv' \
  "$A/trivy-config.json" | sort > "$A/trivy-hits.tsv"
wc -l < "$A/trivy-hits.tsv"   # this is metrics.raw_hits
```

Optional second scanner. It never calls the vendor API with `--skip-download`:

```bash
mkdir -p "$A/checkov"
checkov --directory . --framework terraform kubernetes dockerfile \
  --skip-download --soft-fail --quiet --compact \
  --output json --output sarif --output-file-path "$A/checkov" \
  > "$A/checkov/stdout.txt" 2> "$A/checkov/stderr.txt"
# checkov writes results_json.json and results_sarif.sarif there.
ls "$A/checkov"
```

Terraform modules that are not vendored cannot be resolved offline. The
scanner then skips them: list the skipped modules in the summary.

## 2. Triage every hit

Open the file at the reported line. For each hit, answer in this order:

1. **Is the resource reachable?** A security group rule, a `LoadBalancer`
   service, a public bucket policy, an ingress. No path from outside means
   the hit is hygiene at most.
2. **What does it give?** Shell on a host, data, a role, a way out of the
   container. Name it in the description.
3. **Does another control in the repository already cover it?** A
   `NetworkPolicy`, a public access block resource, a pod security label on
   the namespace. If yes, lower the severity and say why.
4. **Could a control outside the repository cover it?** Account-level
   settings, admission controllers. If you cannot tell, it is a hypothesis.
5. **Is it one cause or several hits?** `privileged: true` raises five
   checks. That is one finding with five rule IDs.

Exposure examples: admin port open to `0.0.0.0/0`, privileged container,
`hostPath: /`, `hostNetwork: true`, IAM `Action: "*"` with `Resource: "*"`,
bucket ACL `public-read`, secrets in plain `env` values.

Hygiene examples: no CPU or memory limits, no HEALTHCHECK, `:latest` tag,
missing access logs, missing versioning, apt without
`--no-install-recommends`.

## 3. Report

- Findings: exposures first, then one grouped hygiene finding per file type.
- `remediation` names the attribute and the value:
  `cidr_blocks = ["10.0.0.0/8"]`, `securityContext.privileged: false`.
- `proof.poc` shows the hit in the raw report, for example:
  `jq '.Results[].Misconfigurations[]? | select(.ID=="KSV-0017")' artifacts/trivy-config.json`
- Fill `metrics.raw_hits`, `metrics.exposures`, `metrics.hygiene`.

## Pitfalls

- Copying the scanner severity. A missing HEALTHCHECK is not "high" because
  a neighbouring check is.
- One finding per rule ID. Group by root cause.
- Calling a bucket "public" because the public access block resource is
  missing. Missing block is a lead; a public ACL or policy is proof.
- Running `terraform init` to resolve modules. It needs the network and
  executes provider code: do not.
- Check IDs changed format across trivy versions (`AVD-AWS-0107`,
  `AWS-0107`). Record the ID exactly as the report prints it.
