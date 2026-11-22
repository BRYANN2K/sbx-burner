"""CVSS v3.1 base score calculator (stdlib only).

Used by the triage gate: a finding that carries a CVSS vector must carry the
score that the vector actually produces.
Specification: https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

import math

_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}
_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]


class CVSSError(ValueError):
    pass


def _roundup(value: float) -> float:
    """Spec-defined round up to one decimal (Appendix A)."""
    as_int = round(value * 100000)
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    parts = vector.strip().split("/")
    if not parts or parts[0] not in ("CVSS:3.1", "CVSS:3.0"):
        raise CVSSError("vector must start with CVSS:3.1 or CVSS:3.0")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            raise CVSSError(f"bad metric {part!r}")
        key, val = part.split(":", 1)
        if key in metrics:
            raise CVSSError(f"duplicate metric {key}")
        metrics[key] = val
    missing = [m for m in _ORDER if m not in metrics]
    if missing:
        raise CVSSError(f"missing base metrics: {', '.join(missing)}")
    if metrics["S"] not in ("U", "C"):
        raise CVSSError("S must be U or C")
    for key, table in _WEIGHTS.items():
        if metrics[key] not in table:
            raise CVSSError(f"bad value for {key}: {metrics[key]!r}")
    if metrics["PR"] not in _PR["U"]:
        raise CVSSError(f"bad value for PR: {metrics['PR']!r}")
    return metrics


def base_score(vector: str) -> float:
    m = parse_vector(vector)
    changed = m["S"] == "C"
    iss = 1 - (1 - _WEIGHTS["C"][m["C"]]) * (1 - _WEIGHTS["I"][m["I"]]) * (1 - _WEIGHTS["A"][m["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    exploitability = 8.22 * _WEIGHTS["AV"][m["AV"]] * _WEIGHTS["AC"][m["AC"]] * _PR[m["S"]][m["PR"]] * _WEIGHTS["UI"][m["UI"]]
    if impact <= 0:
        return 0.0
    total = 1.08 * (impact + exploitability) if changed else impact + exploitability
    return _roundup(min(total, 10))


def severity(score: float) -> str:
    if score == 0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"
