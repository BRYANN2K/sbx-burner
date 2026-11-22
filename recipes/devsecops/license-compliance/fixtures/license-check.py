#!/usr/bin/env python3
"""Check the licences in a CycloneDX SBOM against a policy file.

    python3 fixtures/license-check.py --sbom evidence/artifacts/sbom.cdx.json \
        --policy fixtures/license-policy.yaml --out evidence/artifacts/licence-check.json

Each component gets one decision: allow, review, deny or unknown.
An SPDX expression is reduced like this: ``A OR B`` takes the most permissive
side, ``A AND B`` the most restrictive side, ``A WITH exception`` is read as
``A``. A component with no declared licence, or a licence in no list, gets
the policy's ``unknown`` action. ``applies_to`` is echoed, not applied: the
SBOM carries no dev/shipped marker, so the agent applies it by reading the
lockfile. ``policy_sha256`` fingerprints the policy file the run used.
Exit code: 0 = nothing denied, 1 = at least one denied component,
2 = bad input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

RANK = {"allow": 0, "review": 1, "unknown": 2, "deny": 3}


def read_simple_yaml(path: Path) -> dict:
    """Read the flat YAML the policy uses: ``key: value`` and ``key:`` + ``- item`` lists."""
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
                data[key] = value.strip("\"'")
                current = None
            else:
                data[key] = []
                current = key
        else:
            raise ValueError(f"policy: unsupported line: {raw!r}")
    return data


def load_policy(path: Path) -> dict:
    policy = read_simple_yaml(path)
    for key in ("allow", "review", "deny"):
        if not isinstance(policy.get(key, []), list):
            raise ValueError(f"policy: {key!r} must be a list")
        policy[key] = {str(item).lower() for item in policy.get(key, [])}
    if policy.get("unknown", "review") not in ("allow", "review", "deny"):
        raise ValueError("policy: 'unknown' must be allow, review or deny")
    return policy


def decide_id(spdx_id: str, policy: dict) -> str:
    key = spdx_id.strip().lower()
    for decision in ("deny", "review", "allow"):
        if key in policy[decision]:
            return decision
    return "unknown"


def decide_expression(expression: str, policy: dict) -> str:
    """Reduce an SPDX expression to one decision (no nested precedence beyond AND over OR)."""
    text = expression.replace("(", " ").replace(")", " ")
    best = None
    for alternative in re.split(r"\s+OR\s+", text, flags=re.I):
        worst = "allow"
        for term in re.split(r"\s+AND\s+", alternative, flags=re.I):
            spdx_id = re.split(r"\s+WITH\s+", term.strip(), flags=re.I)[0]
            decision = decide_id(spdx_id, policy) if spdx_id else "unknown"
            if RANK[decision] > RANK[worst]:
                worst = decision
        if best is None or RANK[worst] < RANK[best]:
            best = worst
    return best or "unknown"


def component_licences(component: dict) -> list[str]:
    found = []
    for entry in component.get("licenses") or []:
        if entry.get("expression"):
            found.append(entry["expression"])
        licence = entry.get("license") or {}
        if licence.get("id") or licence.get("name"):
            found.append(licence.get("id") or licence["name"])
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sbom", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    try:
        policy = load_policy(args.policy)
        sbom = json.loads(args.sbom.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"license-check: {exc}", file=sys.stderr)
        return 2

    unknown_action = policy.get("unknown", "review")
    rows = []
    for component in sbom.get("components") or []:
        if component.get("type") == "file":
            continue
        licences = component_licences(component)
        if licences:
            # Several declared licences on one component: all of them apply.
            decision = max((decide_expression(item, policy) for item in licences), key=RANK.__getitem__)
        else:
            decision = "unknown"
        if decision == "unknown":
            decision = unknown_action
        rows.append(
            {
                "name": component.get("name"),
                "version": component.get("version"),
                "purl": component.get("purl"),
                "licences": licences,
                "decision": decision,
            }
        )
    rows.sort(key=lambda row: (-RANK[row["decision"]], str(row["name"])))
    counts = {name: sum(1 for row in rows if row["decision"] == name) for name in RANK}
    result = {
        "policy": str(args.policy),
        "policy_sha256": hashlib.sha256(args.policy.read_bytes()).hexdigest(),
        "applies_to": policy.get("applies_to", "shipped"),
        "unknown_action": unknown_action,
        "components": len(rows),
        "counts": counts,
        "results": rows,
    }
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(counts))
    return 1 if counts["deny"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
