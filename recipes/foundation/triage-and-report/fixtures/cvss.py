#!/usr/bin/env python3
"""CVSS 3.1 base score for one vector, printed as a JSON line.

    python3 fixtures/cvss.py 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
    -> {"vector": "...", "score": 7.5, "severity": "high"}

Stdlib only. Metric values and formulas follow the FIRST CVSS v3.1
specification (Appendix A, including its round-up rule).
"""

from __future__ import annotations

import json
import math
import sys

METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
PR = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}


def roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def parse(vector: str) -> dict[str, str]:
    parts = vector.strip().split("/")
    if len(parts) < 2 or parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
        raise ValueError("vector must start with CVSS:3.0 or CVSS:3.1")
    values: dict[str, str] = {}
    for part in parts[1:]:
        key, sep, val = part.partition(":")
        if not sep or key in values:
            raise ValueError(f"bad metric {part!r}")
        values[key] = val
    missing = [k for k in METRICS if k not in values]
    if missing:
        raise ValueError("missing base metrics: " + ", ".join(missing))
    for key, table in (("AV", W["AV"]), ("AC", W["AC"]), ("UI", W["UI"]), ("C", W["C"]), ("I", W["I"]), ("A", W["A"])):
        if values[key] not in table:
            raise ValueError(f"bad value {key}:{values[key]}")
    if values["S"] not in PR or values["PR"] not in PR[values["S"]]:
        raise ValueError("bad value for S or PR")
    return values


def base_score(v: dict[str, str]) -> float:
    iss = 1 - (1 - W["C"][v["C"]]) * (1 - W["I"][v["I"]]) * (1 - W["A"][v["A"]])
    if iss <= 0:
        return 0.0
    changed = v["S"] == "C"
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    expl = 8.22 * W["AV"][v["AV"]] * W["AC"][v["AC"]] * PR[v["S"]][v["PR"]] * W["UI"][v["UI"]]
    total = (1.08 * (impact + expl)) if changed else (impact + expl)
    return roundup(min(total, 10.0))


def severity(score: float) -> str:
    if score == 0.0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: cvss.py 'CVSS:3.1/AV:.../A:...'", file=sys.stderr)
        return 2
    try:
        score = base_score(parse(argv[1]))
    except ValueError as exc:
        print(f"invalid vector: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"vector": argv[1], "score": score, "severity": severity(score)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
