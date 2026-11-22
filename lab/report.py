"""Render report.md and report.json from gated evidence only."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .evidence import GateResult

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def build(run: dict[str, Any], result: GateResult) -> dict[str, Any]:
    """Assemble the machine-readable report."""
    ev = result.evidence
    findings = sorted(ev.get("findings", []), key=lambda f: (_SEVERITY_ORDER.get(f["severity"], 9), f["id"]))
    counts = {sev: 0 for sev in _SEVERITY_ORDER}
    for finding in findings:
        counts[finding["severity"]] += 1
    return {
        "schema_version": "1",
        "run": run,
        "summary": ev.get("summary", ""),
        "counts": {"findings": len(findings), "hypotheses": len(ev.get("hypotheses", [])), "by_severity": counts},
        "findings": findings,
        "hypotheses": ev.get("hypotheses", []),
        "tools_run": ev.get("tools_run", []),
        "artifacts": ev.get("artifacts", []),
        "gate": {
            "schema_errors": result.schema_errors,
            "demoted": result.demoted,
            "warnings": result.warnings,
            "redactions": result.redactions,
        },
    }


def _cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _target_line(target: Any) -> str:
    if not isinstance(target, dict):
        return f"- Target: {target or 'none'}"
    parts = [
        target.get("kind", "none"),
        str(target.get("repo") or target.get("app") or target.get("image") or target.get("url") or target.get("path") or ""),
    ]
    line = "- Target: " + " ".join(p for p in parts if p)
    identity0 = target.get("identity") or {}
    if identity0.get("commit"):
        line += f" (commit {str(identity0['commit'])[:12]}"
        if identity0.get("pr"):
            line += f", pr #{identity0['pr']}"
        line += ")"
    if target.get("source"):
        line += f" (source: {target['source']})"
    if target.get("cmd") and target.get("kind") == "app":
        line += f" (start: {target['cmd']})"
    if target.get("resolved"):
        line += f" (resolved: {target['resolved']})"
    identity = target.get("identity") or {}
    if identity.get("sha256"):
        line += f" (sha256: {identity['sha256']}"
        if identity.get("git_head"):
            line += f", git {identity['git_head'][:12]}{' dirty' if identity.get('dirty') else ''}"
        line += f", {identity.get('files', 0)} file(s))"
    path_identity = target.get("path_identity") or {}
    if path_identity.get("sha256"):
        line += f" + supporting files at {target.get('path')} (sha256: {path_identity['sha256']}, {path_identity.get('files', 0)} file(s))"
    if target.get("added_by_runner"):
        line += " [" + ", ".join(target["added_by_runner"]) + " added by runner]"
    return line


def render_markdown(report: dict[str, Any]) -> str:
    run = report["run"]
    out: list[str] = [f"# Lab report: {run['recipe']}", ""]
    out += [
        f"- Run: `{run['id']}`",
        f"- Agent: {run.get('agent', 'n/a')}",
        f"- Scope: {run.get('scope_id') or 'none'}",
        _target_line(run.get("target")),
        f"- Started: {run.get('started', 'n/a')}",
        f"- Status: {run.get('status', 'n/a')}",
        "",
        "## Summary",
        "",
        report["summary"] or "_No summary._",
        "",
    ]
    counts = report["counts"]
    sev = ", ".join(f"{n} {name}" for name, n in counts["by_severity"].items() if n) or "none"
    out += [f"Findings: {counts['findings']} ({sev}). Hypotheses: {counts['hypotheses']}.", ""]

    out += ["## Findings", ""]
    if not report["findings"]:
        out += ["No proven finding.", ""]
    else:
        out += ["| ID | Severity | CVSS | Title | Target |", "| --- | --- | --- | --- | --- |"]
        for f in report["findings"]:
            score = f.get("cvss", {}).get("score", "")
            out.append(f"| {_cell(f['id'])} | {f['severity']} | {score} | {_cell(f['title'])} | {_cell(f['target'])} |")
        out.append("")
        for f in report["findings"]:
            out += [f"### {f['id']}: {f['title']}", ""]
            out.append(f"- Severity: {f['severity']}")
            if "cvss" in f:
                out.append(f"- CVSS: {f['cvss']['score']} (`{f['cvss']['vector']}`)")
            for key, label in (("cwe", "CWE"), ("target", "Target"), ("location", "Location"), ("tool", "Tool"), ("rule", "Rule")):
                if f.get(key):
                    out.append(f"- {label}: {f[key]}")
            out += ["", f["description"], "", "Proof of concept:", "", "```text", f["proof"]["poc"], "```", ""]
            out.append("Artifacts: " + ", ".join(f"`{a}`" for a in f["proof"]["artifacts"]))
            if f.get("remediation"):
                out += ["", f"Remediation: {f['remediation']}"]
            if f.get("references"):
                out += ["", "References: " + ", ".join(f["references"])]
            out.append("")

    out += ["## Hypotheses (unproven)", ""]
    if not report["hypotheses"]:
        out += ["None.", ""]
    for h in report["hypotheses"]:
        line = f"- **{h['id']}**: {h['title']}. {h['rationale']}"
        if h.get("demoted_reason"):
            line += f" (demoted from {h['demoted_from']}: {h['demoted_reason']})"
        if h.get("next_step"):
            line += f" Next: {h['next_step']}"
        out.append(line)
    if report["hypotheses"]:
        out.append("")

    out += ["## Tools run", ""]
    if report["tools_run"]:
        out += ["| Tool | Version | Exit | Command |", "| --- | --- | --- | --- |"]
        for t in report["tools_run"]:
            out.append(f"| {_cell(t['name'])} | {_cell(t.get('version', ''))} | {t['exit_code']} | `{_cell(t['command'])}` |")
    else:
        out.append("None recorded.")
    out.append("")

    out += ["## Artifacts", ""]
    if report["artifacts"]:
        for a in report["artifacts"]:
            digest = f" sha256:{a['sha256'][:16]}" if a.get("sha256") else ""
            out.append(f"- `{a['path']}`{digest} {a.get('description', '')}".rstrip())
    else:
        out.append("None recorded.")
    out.append("")

    gate = report["gate"]
    out += ["## Evidence gate", ""]
    out.append(f"- Schema errors: {len(gate['schema_errors'])}")
    out.append(f"- Findings demoted to hypotheses: {len(gate['demoted'])}")
    out.append(f"- Secrets redacted: {gate['redactions']}")
    for err in gate["schema_errors"]:
        out.append(f"  - schema: {err}")
    for warning in gate["warnings"]:
        out.append(f"  - warning: {warning}")
    out.append("")
    return "\n".join(out)


def write(run_dir: Path, run: dict[str, Any], result: GateResult) -> dict[str, Any]:
    report = build(run, result)
    (run_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (run_dir / "report.md").write_text(render_markdown(report), encoding="utf-8")
    return report
