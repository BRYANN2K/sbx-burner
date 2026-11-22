#!/usr/bin/env python3
"""Reconcile a trivy JSON report and a grype JSON report on one image.

    python3 fixtures/reconcile.py --trivy evidence/artifacts/trivy.json \
        --grype evidence/artifacts/grype.json --out evidence/artifacts/reconciled.json

Emits one entry per unique (cve, package) pair: which scanner(s) saw it, the
severity each assigned, the fix version each knows (empty when none), and an
NVD CVSS 3.1 vector when either report carries one. Prints the counts to
stdout (one JSON line). Exit code: 0 always; 2 on bad input.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SEVERITY_RANK = {"unknown": 0, "negligible": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
RANK_SEVERITY = {rank: name for name, rank in SEVERITY_RANK.items()}


def nvd_vector_trivy(vuln: dict) -> str | None:
    for source in ("nvd", "redhat"):
        entry = (vuln.get("CVSS") or {}).get(source) or {}
        vector = entry.get("V3Vector")
        if vector:
            return vector
    return None


def nvd_vector_grype(vuln: dict) -> str | None:
    for entry in vuln.get("cvss") or []:
        if "nvd" in str(entry.get("source", "")) and entry.get("vector", "").startswith("CVSS:3."):
            return entry["vector"]
    for entry in vuln.get("cvss") or []:
        if entry.get("vector", "").startswith("CVSS:3."):
            return entry["vector"]
    return None


def merge(pair: dict, scanner: str, severity: str, fixed: str | None, vector: str | None) -> None:
    if scanner not in pair["scanners"]:
        pair["scanners"].append(scanner)
    pair["severities"][scanner] = severity.lower()
    if fixed and fixed not in pair["fixed_versions"]:
        pair["fixed_versions"].append(fixed)
    if pair["cvss_vector"] is None and vector:
        pair["cvss_vector"] = vector


def pairs_trivy(path: Path) -> dict[tuple[str, str], dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    pairs: dict[tuple[str, str], dict] = {}
    for result in data.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            key = (vuln.get("VulnerabilityID") or "", vuln.get("PkgName") or "")
            pair = pairs.setdefault(key, _new_pair(*key))
            merge(pair, "trivy", vuln.get("Severity", "unknown"), vuln.get("FixedVersion"), nvd_vector_trivy(vuln))
            if vuln.get("InstalledVersion") and not pair["installed_version"]:
                pair["installed_version"] = vuln["InstalledVersion"]
    return pairs


def pairs_grype(path: Path) -> dict[tuple[str, str], dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    pairs: dict[tuple[str, str], dict] = {}
    for match in data.get("matches") or []:
        vuln, artifact = match.get("vulnerability") or {}, match.get("artifact") or {}
        key = (vuln.get("id") or "", artifact.get("name") or "")
        pair = pairs.setdefault(key, _new_pair(*key))
        fix = (vuln.get("fix") or {}).get("versions") or []
        merge(pair, "grype", vuln.get("severity", "unknown"), fix[0] if fix else None, nvd_vector_grype(vuln))
        if artifact.get("version") and not pair["installed_version"]:
            pair["installed_version"] = artifact["version"]
    return pairs


def _new_pair(cve: str, package: str) -> dict:
    return {
        "cve": cve,
        "package": package,
        "installed_version": "",
        "scanners": [],
        "severities": {},
        "union_severity": "unknown",
        "fixed_versions": [],
        "cvss_vector": None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--trivy", required=True, type=Path)
    parser.add_argument("--grype", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    try:
        merged = pairs_trivy(args.trivy)
    except (OSError, ValueError) as exc:
        print(f"reconcile: cannot read trivy report: {exc}", file=sys.stderr)
        return 2
    try:
        for key, pair in pairs_grype(args.grype).items():
            target = merged.setdefault(key, _new_pair(*key))
            target["installed_version"] = target["installed_version"] or pair["installed_version"]
            for scanner in pair["scanners"]:
                merge(
                    target,
                    scanner,
                    pair["severities"][scanner],
                    pair["fixed_versions"][0] if pair["fixed_versions"] else None,
                    pair["cvss_vector"],
                )
    except (OSError, ValueError) as exc:
        print(f"reconcile: cannot read grype report: {exc}", file=sys.stderr)
        return 2

    rows = list(merged.values())
    for pair in rows:
        pair["scanners"].sort()
        pair["union_severity"] = RANK_SEVERITY[max(SEVERITY_RANK.get(s, 0) for s in pair["severities"].values())]
    rows.sort(key=lambda p: (-SEVERITY_RANK[p["union_severity"]], p["cve"], p["package"]))

    counts = {
        "total": len(rows),
        "fixable": sum(1 for p in rows if p["fixed_versions"]),
        "only_trivy": sum(1 for p in rows if p["scanners"] == ["trivy"]),
        "only_grype": sum(1 for p in rows if p["scanners"] == ["grype"]),
        "by_union_severity": {
            sev: sum(1 for p in rows if p["union_severity"] == sev)
            for sev in ("critical", "high", "medium", "low", "negligible", "unknown")
        },
    }
    args.out.write_text(json.dumps({"counts": counts, "pairs": rows}, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(counts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
