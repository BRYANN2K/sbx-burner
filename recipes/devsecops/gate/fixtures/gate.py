#!/usr/bin/env python3
"""Merge the scanner reports of devsecops/gate and apply the gate policy.

    python3 fixtures/gate.py --artifacts evidence/artifacts \
        --policy fixtures/gate-policy.yaml --target /home/agent/target

Reads, when present, from the artifacts directory:
    gitleaks.json  osv.json  semgrep.json  trivy-config.json  trivy-image.json
    sbom.cdx.json  and every matching <name>.sarif
Writes into the same directory:
    gate.sarif        one SARIF 2.1.0 file, one run per tool
    gate-result.json  counts per check, blocking items, decision, policy hash
    pr-summary.md     the summary to post on the pull request
Exit code: 0 = gate passed, 1 = gate failed, 2 = bad input.
Standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

CHECKS = ("secrets", "sca", "sast", "iac", "container", "sbom", "licence")
REPORTS = {
    "secrets": "gitleaks.json",
    "sca": "osv.json",
    "sast": "semgrep.json",
    "iac": "trivy-config.json",
    "container": "trivy-image.json",
    "sbom": "sbom.cdx.json",
    "licence": "sbom.cdx.json",
}
# The severity band each check reads from the policy.
SEVERITY_KEYS = {"sca", "sast", "iac", "container"}
# The JSON shape a report must have to count as a real report: a report that
# lacks its top-level key is an error, never an implicit pass.
REPORT_SHAPE = {
    "secrets": ("array", None),
    "sca": ("object", "results"),
    "sast": ("object", "results"),
    "iac": ("object", "Results"),
    "container": ("object", "Results"),
    "sbom": ("object", "components"),
    "licence": ("object", "components"),
}
SARIF_INPUTS = ("gitleaks.sarif", "osv.sarif", "semgrep.sarif", "trivy-config.sarif", "trivy-image.sarif")
SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "unknown": "note"}
SKIP_DIRS = {".git", "node_modules", "vendor", ".terraform"}


def read_policy(path: Path) -> dict:
    """Read the flat YAML the policy uses: ``key: value``, ``key: [a, b]``, ``key:`` + ``- item``."""
    data: dict = {}
    current = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split(" #")[0].rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        stripped = line.strip()
        if stripped.startswith("- "):
            if current is None:
                raise ValueError(f"policy: list item outside a key: {raw!r}")
            data[current].append(stripped[2:].strip().strip("\"'"))
        elif ":" in stripped and not line.startswith(" "):
            key, _, value = stripped.partition(":")
            value = value.strip()
            if value.startswith("[") and value.endswith("]"):
                data[key] = [item.strip().strip("\"'") for item in value[1:-1].split(",") if item.strip()]
                current = None
            elif value:
                data[key] = {"true": True, "false": False}.get(value.lower(), value.strip("\"'"))
                current = None
            else:
                data[key] = []
                current = key
        else:
            raise ValueError(f"policy: unsupported line: {raw!r}")
    return data


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def band(score) -> str:
    """CVSS base score to severity band."""
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    return "low" if value > 0 else "unknown"


def item(check, tool, rule, location, severity, title, fix=""):
    return {"check": check, "tool": tool, "rule": rule, "location": location, "severity": severity, "title": title, "fix": fix}


def collect_secrets(report, policy):
    items = [
        item("secrets", "gitleaks", leak.get("RuleID", ""), f"{leak.get('File')}:{leak.get('StartLine')}", "high", leak.get("Description", "leaked secret"))
        for leak in report or []
    ]
    return items, (items if policy.get("secrets_fail_on", "any") == "any" else [])


def collect_sca(report, policy):
    items = []
    for result in report.get("results") or []:
        source = (result.get("source") or {}).get("path", "")
        for pkg in result.get("packages") or []:
            info = pkg.get("package") or {}
            vulns = {v.get("id"): v for v in pkg.get("vulnerabilities") or []}
            for group in pkg.get("groups") or []:
                fixed = sorted(
                    {
                        event["fixed"]
                        for vid in group.get("ids") or []
                        for affected in (vulns.get(vid) or {}).get("affected") or []
                        for rng in affected.get("ranges") or []
                        for event in rng.get("events") or []
                        if event.get("fixed")
                    }
                )
                first = vulns.get((group.get("ids") or [""])[0]) or {}
                items.append(
                    item(
                        "sca",
                        "osv-scanner",
                        (group.get("ids") or ["?"])[0],
                        f"{Path(source).name}:{info.get('name')}@{info.get('version')}",
                        band(group.get("max_severity")),
                        first.get("summary") or "known vulnerability",
                        ", ".join(fixed),
                    )
                )
    wanted = set(policy.get("sca_fail_severities") or [])
    need_fix = policy.get("sca_only_with_fix", True)
    return items, [i for i in items if i["severity"] in wanted and (i["fix"] or not need_fix)]


def collect_sast(report, policy):
    items = []
    for result in report.get("results") or []:
        extra = result.get("extra") or {}
        raw = str(extra.get("severity", "")).upper()
        severity = SEMGREP_SEVERITY.get(raw, raw.lower() if raw.lower() in SARIF_LEVEL else "unknown")
        location = f"{result.get('path')}:{(result.get('start') or {}).get('line')}"
        items.append(item("sast", "semgrep", result.get("check_id", ""), location, severity, str(extra.get("message", "")).split(". ")[0][:160]))
    wanted = set(policy.get("sast_fail_severities") or [])
    return items, [i for i in items if i["severity"] in wanted]


def collect_trivy(report, policy, check):
    items = []
    for result in report.get("Results") or []:
        target = result.get("Target", "")
        for mis in result.get("Misconfigurations") or []:
            if mis.get("Status", "FAIL") != "FAIL":
                continue
            line = (mis.get("CauseMetadata") or {}).get("StartLine")
            location = f"{target}:{line}" if line else target
            items.append(item(check, "trivy", mis.get("ID", ""), location, str(mis.get("Severity", "")).lower(), mis.get("Title", ""), mis.get("Resolution", "")))
        for vuln in result.get("Vulnerabilities") or []:
            location = f"{target}:{vuln.get('PkgName')}@{vuln.get('InstalledVersion')}"
            title = vuln.get("Title") or "known vulnerability"
            items.append(item(check, "trivy", vuln.get("VulnerabilityID", ""), location, str(vuln.get("Severity", "")).lower(), title, vuln.get("FixedVersion", "")))
    wanted = set(policy.get(f"{check}_fail_severities") or [])
    need_fix = check == "container" and policy.get("container_only_with_fix", True)
    return items, [i for i in items if i["severity"] in wanted and (i["fix"] or not need_fix)]


def denied_licence(expression: str, deny: set[str]) -> bool:
    """True when every OR alternative of an SPDX expression contains a denied id."""
    text = expression.replace("(", " ").replace(")", " ")
    for alternative in re.split(r"\s+OR\s+", text, flags=re.I):
        ids = [re.split(r"\s+WITH\s+", term.strip(), flags=re.I)[0].lower() for term in re.split(r"\s+AND\s+", alternative, flags=re.I)]
        if not any(spdx_id in deny for spdx_id in ids):
            return False
    return True


def collect_licence(sbom, policy):
    deny = {str(entry).lower() for entry in policy.get("licence_deny") or []}
    items, unknown = [], 0
    for component in sbom.get("components") or []:
        if component.get("type") == "file":
            continue
        declared = []
        for entry in component.get("licenses") or []:
            licence = entry.get("license") or {}
            value = entry.get("expression") or licence.get("id") or licence.get("name")
            if value:
                declared.append(value)
        if not declared:
            unknown += 1
        for value in declared:
            if denied_licence(value, deny):
                location = component.get("purl") or f"{component.get('name')}@{component.get('version')}"
                items.append(item("licence", "syft", "licence-denied", location, "high", f"{value} is on the deny list", "replace the component or get a written exception"))
    return items, list(items), unknown


def has_dockerfile(target: Path | None) -> bool:
    if target is None or not target.is_dir():
        return False
    for path in target.rglob("*"):
        if SKIP_DIRS.intersection(path.parts):
            continue
        if path.is_file() and (path.name == "Dockerfile" or path.name.startswith("Dockerfile.") or path.name.endswith(".dockerfile")):
            return True
    return False


def merge_sarif(artifacts: Path, licence_items: list[dict]) -> dict:
    runs = []
    for name in SARIF_INPUTS:
        path = artifacts / name
        if not path.is_file():
            continue
        for run in load_json(path).get("runs") or []:
            # Keep only the rules that have a result: scanners list every rule they know.
            used = {result.get("ruleId") for result in run.get("results") or []}
            driver = (run.get("tool") or {}).get("driver") or {}
            if "rules" in driver:
                driver["rules"] = [rule for rule in driver["rules"] if rule.get("id") in used]
                index = {rule.get("id"): i for i, rule in enumerate(driver["rules"])}
                for result in run.get("results") or []:
                    if "ruleIndex" in result and result.get("ruleId") in index:
                        result["ruleIndex"] = index[result["ruleId"]]
            runs.append(run)
    if licence_items:
        runs.append(
            {
                "tool": {"driver": {"name": "licence-policy", "rules": [{"id": "licence-denied", "shortDescription": {"text": "Licence on the deny list"}}]}},
                "results": [
                    {
                        "ruleId": "licence-denied",
                        "level": SARIF_LEVEL[entry["severity"]],
                        "message": {"text": f"{entry['location']}: {entry['title']}"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "sbom.cdx.json"}}, "logicalLocations": [{"name": entry["location"]}]}],
                    }
                    for entry in licence_items
                ],
            }
        )
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": runs}


def render_summary(result: dict) -> str:
    verdict = "PASSED" if result["gate_passed"] else "FAILED"
    lines = [f"## Security gate: {verdict}", "", "| Check | Status | Findings | Blocking |", "| --- | --- | --- | --- |"]
    for name in CHECKS:
        check = result["checks"][name]
        lines.append(f"| {name} | {check['status']} | {check['total']} | {check['blocking']} |")
    lines.append("")
    if result["reasons"]:
        lines.append("### Why the gate failed")
        lines.append("")
        lines.extend(f"- {reason}" for reason in result["reasons"])
        lines.append("")
    if result["blocking_items"]:
        lines.append("### Blocking findings")
        lines.append("")
        lines.append("| Check | Severity | Rule | Location | Fix |")
        lines.append("| --- | --- | --- | --- | --- |")
        for entry in result["blocking_items"][:25]:
            lines.append(f"| {entry['check']} | {entry['severity']} | `{entry['rule']}` | `{entry['location']}` | {(entry['fix'] or '-')[:120]} |")
        if len(result["blocking_items"]) > 25:
            lines.append(f"| ... | | | {len(result['blocking_items']) - 25} more in `gate-result.json` | |")
        lines.append("")
    lines.append(f"Policy: `{result['policy']}` (sha256 `{result['policy_sha256'][:12]}`). Full results: `gate.sarif`.")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--target", type=Path, default=None, help="scanned directory, used to see whether a Dockerfile exists")
    args = parser.parse_args()
    try:
        policy = read_policy(args.policy)
        policy_sha256 = hashlib.sha256(args.policy.read_bytes()).hexdigest()
    except (OSError, ValueError) as exc:
        print(f"gate: {exc}", file=sys.stderr)
        return 2

    if "required_checks" not in policy:
        print("gate: policy has no required_checks: refusing to run a gate that cannot fail", file=sys.stderr)
        return 2
    required = set(policy.get("required_checks") or [])
    dockerfile = has_dockerfile(args.target)
    if dockerfile and policy.get("container_required_with_dockerfile", True):
        required.add("container")
    missing_keys = [f"{name}_fail_severities" for name in sorted(required & SEVERITY_KEYS) if f"{name}_fail_severities" not in policy]
    if missing_keys:
        print(f"gate: policy is missing {', '.join(missing_keys)}: a required check needs its severity bar", file=sys.stderr)
        return 2

    checks: dict[str, dict] = {}
    blocking_items: list[dict] = []
    reasons: list[str] = []
    licence_items: list[dict] = []
    for name in CHECKS:
        path = args.artifacts / REPORTS[name]
        entry = {"status": "skipped", "total": 0, "blocking": 0, "report": REPORTS[name]}
        checks[name] = entry
        if not path.is_file() or path.stat().st_size == 0:
            if name in required:
                entry["status"] = "missing"
                if policy.get("on_check_error", "fail") == "fail":
                    reasons.append(f"{name}: required report {REPORTS[name]} is missing")
            continue
        try:
            report = load_json(path)
            kind, top_key = REPORT_SHAPE[name]
            if (kind == "array" and not isinstance(report, list)) or (kind == "object" and not (isinstance(report, dict) and top_key in report)):
                raise ValueError(f"{REPORTS[name]} has no top-level {top_key or 'array'}")
            if name == "secrets":
                items, blocking = collect_secrets(report, policy)
            elif name == "sca":
                items, blocking = collect_sca(report, policy)
            elif name == "sast":
                items, blocking = collect_sast(report, policy)
            elif name in ("iac", "container"):
                items, blocking = collect_trivy(report, policy, name)
            elif name == "licence":
                items, blocking, unknown = collect_licence(report, policy)
                entry["unknown_licences"] = unknown
                licence_items = items
            else:  # sbom: present and not empty
                items = [c for c in report.get("components") or [] if c.get("type") != "file"]
                blocking = []
                entry["components"] = len(items)
                if not items and name in required:
                    reasons.append("sbom: the SBOM lists no component")
        except (ValueError, AttributeError, TypeError) as exc:
            entry["status"] = "error"
            if name in required and policy.get("on_check_error", "fail") == "fail":
                reasons.append(f"{name}: cannot read {REPORTS[name]} ({exc})")
            continue
        entry["status"] = "fail" if blocking else "pass"
        entry["total"] = len(items)
        entry["blocking"] = len(blocking)
        if blocking:
            blocking_items.extend(blocking)
            reasons.append(f"{name}: {len(blocking)} blocking finding(s)")

    result = {
        "gate_passed": not reasons,
        "policy": args.policy.name,
        "policy_sha256": policy_sha256,
        "dockerfile_found": dockerfile,
        "checks": checks,
        "reasons": reasons,
        "blocking_items": blocking_items,
    }
    (args.artifacts / "gate.sarif").write_text(json.dumps(merge_sarif(args.artifacts, licence_items), indent=1) + "\n", encoding="utf-8")
    (args.artifacts / "gate-result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    (args.artifacts / "pr-summary.md").write_text(render_summary(result), encoding="utf-8")
    print(f"gate {'passed' if result['gate_passed'] else 'failed'}: " + ("; ".join(reasons) or "no blocking finding"))
    return 0 if result["gate_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
