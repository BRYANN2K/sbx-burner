"""Evidence loading, the "no proof, no finding" gate and redaction."""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import cvss, jsonschema_lite

SCHEMA_PATH = Path(__file__).parent / "schema" / "evidence.schema.json"
EVIDENCE_FILE = "evidence.json"

# Patterns for secrets that must never reach a report. Each keeps a short
# prefix so a reader can still tell which credential was found.
_REDACTIONS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("bearer", re.compile(r"(?i)\b(authorization:\s*bearer\s+)[A-Za-z0-9._~+/=-]{16,}")),
    ("password-assignment", re.compile(r"(?i)\b((?:password|passwd|secret|api[_-]?key|token)\s*[=:]\s*)(['\"]?)[^\s'\"]{8,}\2")),
)


def redact(text: str, extra_values: list[str] | tuple[str, ...] = ()) -> tuple[str, int]:
    """Mask secrets in ``text``. Returns the new text and the number of hits.

    ``extra_values`` are literal strings (for example --app-env values) that
    are masked wherever they appear.
    """
    count = 0
    for value in extra_values:
        if value and value in text:
            count += text.count(value)
            text = text.replace(value, "[REDACTED:app-env]")
    for label, pattern in _REDACTIONS:

        def _sub(match: re.Match[str], label: str = label) -> str:
            nonlocal count
            count += 1
            if label in ("bearer", "password-assignment"):
                return f"{match.group(1)}[REDACTED:{label}]"
            return f"{match.group(0)[:4]}[REDACTED:{label}]"

        text = pattern.sub(_sub, text)
    return text, count


def redact_obj(obj: Any, extra_values: list[str] | tuple[str, ...] = ()) -> tuple[Any, int]:
    """Recursively redact every string in a JSON-like object."""
    total = 0

    def walk(value: Any) -> Any:
        nonlocal total
        if isinstance(value, str):
            new, n = redact(value, extra_values)
            total += n
            return new
        if isinstance(value, list):
            return [walk(v) for v in value]
        if isinstance(value, dict):
            return {k: walk(v) for k, v in value.items()}
        return value

    return walk(obj), total


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class GateResult:
    evidence: dict[str, Any]
    schema_errors: list[str] = field(default_factory=list)
    demoted: list[dict[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    redactions: int = 0

    @property
    def ok(self) -> bool:
        return not self.schema_errors


def empty(recipe_id: str, summary: str) -> dict[str, Any]:
    return {
        "schema_version": "1",
        "recipe": recipe_id,
        "summary": summary,
        "tools_run": [],
        "findings": [],
        "hypotheses": [],
        "artifacts": [],
    }


def load(evidence_dir: Path) -> dict[str, Any]:
    path = evidence_dir / EVIDENCE_FILE
    if not path.is_file():
        raise FileNotFoundError(f"no {EVIDENCE_FILE} in {evidence_dir}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: evidence must be a JSON object")
    return data


def _inside(base: Path, rel: str) -> Path | None:
    """Resolve ``rel`` under ``base``; None when it escapes or is absolute."""
    if not rel or rel.startswith(("/", "~")):
        return None
    candidate = (base / rel).resolve()
    try:
        candidate.relative_to(base.resolve())
    except ValueError:
        return None
    return candidate


def _proof_problem(finding: dict[str, Any], evidence_dir: Path) -> str | None:
    proof = finding.get("proof") or {}
    if not str(proof.get("poc") or "").strip():
        return "no PoC"
    artifacts = proof.get("artifacts") or []
    if not artifacts:
        return "no artifact"
    for rel in artifacts:
        path = _inside(evidence_dir, rel)
        if path is None:
            return f"artifact path escapes evidence/: {rel}"
        if not path.is_file():
            return f"artifact missing: {rel}"
        if path.stat().st_size == 0:
            return f"artifact is empty: {rel}"
    return None


def gate(data: dict[str, Any], evidence_dir: Path, scope: Any = None, extra_values: list[str] | tuple[str, ...] = ()) -> GateResult:
    """Apply the evidence gate.

    - validate against the evidence schema
    - demote findings without a PoC and existing artifacts to ``hypotheses``
    - demote findings whose target is outside the scope
    - check CVSS vectors against their scores and align the severity
    - hash artifacts and redact secrets from every text field
    """
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    result = GateResult(evidence=copy.deepcopy(data))
    result.schema_errors = jsonschema_lite.validate(data, schema)
    if result.schema_errors:
        return result

    ev = result.evidence
    kept: list[dict[str, Any]] = []
    for finding in ev["findings"]:
        problem = _proof_problem(finding, evidence_dir)
        if problem is None and scope is not None and scope.target_hosts:
            host = _host_of(finding["target"])
            if host and not scope.in_scope(host):
                problem = f"target {host} is out of scope"
        if problem is None and "cvss" in finding:
            try:
                expected = cvss.base_score(finding["cvss"]["vector"])
            except cvss.CVSSError as exc:
                problem = f"invalid CVSS vector: {exc}"
            else:
                if abs(expected - float(finding["cvss"]["score"])) > 0.05:
                    result.warnings.append(f"{finding['id']}: CVSS score {finding['cvss']['score']} corrected to {expected} (from vector)")
                    finding["cvss"]["score"] = expected
                sev = cvss.severity(expected)
                if sev != finding["severity"]:
                    result.warnings.append(f"{finding['id']}: severity {finding['severity']} corrected to {sev} (from CVSS)")
                    finding["severity"] = sev
        if problem is None:
            kept.append(finding)
            continue
        result.demoted.append({"id": finding["id"], "reason": problem})
        ev["hypotheses"].append(
            {
                "id": f"H-{finding['id']}",
                "title": finding["title"],
                "rationale": finding["description"],
                "next_step": "Produce a PoC and attach the artifacts that prove it.",
                "demoted_from": finding["id"],
                "demoted_reason": problem,
            }
        )
    ev["findings"] = kept

    for artifact in ev["artifacts"]:
        path = _inside(evidence_dir, artifact["path"])
        if path is None or not path.is_file():
            result.warnings.append(f"artifact listed but not found: {artifact['path']}")
            continue
        artifact["sha256"] = sha256_file(path)

    result.evidence, result.redactions = redact_obj(ev, extra_values)
    return result


# Last labels that mark a file name rather than a host in a scheme-less target
# (``app.py:20``, ``photo.png``). A few are also real TLDs; such hosts are still
# held by the sandbox network policy, which is the first line of defence.
_FILE_SUFFIXES = frozenset(
    "py js ts go rs c h cc cpp java kt rb php cs swift sh ps1 pl lua "
    "json yaml yml toml ini cfg conf xml html htm md txt csv log lock "
    "png jpg jpeg gif svg pdf bin so dll exe elf zip gz tgz tar pcap pcapng".split()
)
_BARE_HOST_RE = re.compile(r"^(?:[a-z0-9_-]+\.)+([a-z]{2,63})$", re.I)


def _host_of(target: str) -> str | None:
    """Extract ``host[:port]`` from a finding target, if it names a host.

    URL targets give their authority. A scheme-less target is a host when its
    leading ``host[:port]`` token is an IP address, ``localhost`` or a dotted
    host name; file paths and plain labels are not hosts.
    """
    text = target.strip()
    match = re.match(r"^[a-z][a-z0-9+.-]*://([^/\s?#]+)", text, re.I)
    if match:
        return match.group(1).rsplit("@", 1)[-1]
    if not text:
        return None
    token = re.split(r"[\s/?#]", text, maxsplit=1)[0].rsplit("@", 1)[-1]
    host, port = token, None
    v6 = re.match(r"^\[([0-9a-f:.]+)\](?::(\d+))?$", token, re.I)
    if v6:
        host, port = v6.group(1), v6.group(2)
    elif token.count(":") == 1:
        host, port = token.split(":")
        if not port.isdigit():
            return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if host.lower() != "localhost":
            name = _BARE_HOST_RE.match(host)
            if not name or name.group(1).lower() in _FILE_SUFFIXES:
                return None
    if v6:
        return host  # scope.split_host keeps bare IPv6 whole; match on the address
    return f"{host}:{port}" if port else host
