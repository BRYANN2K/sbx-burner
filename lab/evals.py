"""Recipe evals: does a run produce the evidence the recipe promises?

``evals/eval.yaml`` lists checks. They run against a golden fixture (offline,
used by CI and ``lab lint``) or against a real run directory
(``python -m lab eval <recipe> --run runs/<id>``).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import evidence as evidence_mod
from . import miniyaml, report
from .recipe import Recipe


@dataclass
class CheckResult:
    check: str
    passed: bool
    detail: str = ""


def _fullmatch(pattern: Any, value: Any) -> bool:
    return value is not None and re.fullmatch(str(pattern), str(value), re.S) is not None


def _where(items: list[dict[str, Any]], where: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in items if all(_fullmatch(pat, item.get(key)) for key, pat in where.items())]


class _Context:
    def __init__(self, result: evidence_mod.GateResult, evidence_dir: Path, report_md: str) -> None:
        self.result = result
        self.ev = result.evidence
        self.dir = evidence_dir
        self.report_md = report_md


def _tool_ran(ctx: _Context, c: dict[str, Any]) -> tuple[bool, str]:
    names = [t["name"] for t in ctx.ev["tools_run"]]
    return any(_fullmatch(c["name"], n) for n in names), f"tools run: {names}"


def _min_findings(ctx: _Context, c: dict[str, Any]) -> tuple[bool, str]:
    matched = _where(ctx.ev["findings"], c.get("where") or {})
    return len(matched) >= int(c.get("count", 1)), f"{len(matched)} matching finding(s)"


def _max_findings(ctx: _Context, c: dict[str, Any]) -> tuple[bool, str]:
    matched = _where(ctx.ev["findings"], c.get("where") or {})
    return len(matched) <= int(c.get("count", 0)), f"{len(matched)} matching finding(s)"


def _min_hypotheses(ctx: _Context, c: dict[str, Any]) -> tuple[bool, str]:
    matched = _where(ctx.ev["hypotheses"], c.get("where") or {})
    return len(matched) >= int(c.get("count", 1)), f"{len(matched)} matching hypothesis(es)"


def _artifact_exists(ctx: _Context, c: dict[str, Any]) -> tuple[bool, str]:
    hits = [p for p in ctx.dir.glob(c["path"]) if p.is_file() and p.stat().st_size > 0]
    return bool(hits), f"{len(hits)} file(s) match {c['path']}"


def _artifact_contains(ctx: _Context, c: dict[str, Any]) -> tuple[bool, str]:
    for path in ctx.dir.glob(c["path"]):
        if path.is_file() and re.search(c["pattern"], path.read_text(encoding="utf-8", errors="replace")):
            return True, f"{path.name} matches"
    return False, f"no file matching {c['path']} contains {c['pattern']!r}"


def _artifact_absent(ctx: _Context, c: dict[str, Any]) -> tuple[bool, str]:
    """Pass when no file under evidence/ matching ``path`` contains ``pattern``.

    Unlike report_excludes, this reads the raw files the agent wrote, which the
    gate does not redact (for example: no private key left in an artifact).
    """
    glob = c.get("path") or "**/*"
    hits = [
        str(path.relative_to(ctx.dir))
        for path in sorted(ctx.dir.glob(glob))
        if path.is_file() and re.search(c["pattern"], path.read_text(encoding="utf-8", errors="replace"))
    ]
    return not hits, f"{c['pattern']!r} found in: {hits}" if hits else f"no file matching {glob} contains {c['pattern']!r}"


def _no_demotions(ctx: _Context, c: dict[str, Any]) -> tuple[bool, str]:
    return not ctx.result.demoted, f"demoted: {ctx.result.demoted}"


def _demoted(ctx: _Context, c: dict[str, Any]) -> tuple[bool, str]:
    ids = [d["id"] for d in ctx.result.demoted]
    return c["id"] in ids, f"demoted: {ids}"


def _report_contains(ctx: _Context, c: dict[str, Any]) -> tuple[bool, str]:
    return c["text"] in ctx.report_md, "report.md"


def _report_excludes(ctx: _Context, c: dict[str, Any]) -> tuple[bool, str]:
    return re.search(c["pattern"], ctx.report_md) is None, "report.md"


def _summary_matches(ctx: _Context, c: dict[str, Any]) -> tuple[bool, str]:
    return re.search(c["pattern"], ctx.ev["summary"], re.S) is not None, "summary"


def _metric(ctx: _Context, c: dict[str, Any]) -> tuple[bool, str]:
    value = (ctx.ev.get("metrics") or {}).get(c["name"])
    if value is None:
        return False, f"metric {c['name']} missing"
    if "min" in c and value < c["min"]:
        return False, f"{c['name']}={value} < {c['min']}"
    if "max" in c and value > c["max"]:
        return False, f"{c['name']}={value} > {c['max']}"
    if "equals" in c and value != c["equals"]:
        return False, f"{c['name']}={value!r} != {c['equals']!r}"
    return True, f"{c['name']}={value!r}"


CHECKS: dict[str, tuple[Callable[[_Context, dict[str, Any]], tuple[bool, str]], tuple[str, ...]]] = {
    "tool_ran": (_tool_ran, ("name",)),
    "min_findings": (_min_findings, ()),
    "max_findings": (_max_findings, ()),
    "min_hypotheses": (_min_hypotheses, ()),
    "artifact_exists": (_artifact_exists, ("path",)),
    "artifact_contains": (_artifact_contains, ("path", "pattern")),
    "artifact_absent": (_artifact_absent, ("pattern",)),
    "no_demotions": (_no_demotions, ()),
    "demoted": (_demoted, ("id",)),
    "report_contains": (_report_contains, ("text",)),
    "report_excludes": (_report_excludes, ("pattern",)),
    "summary_matches": (_summary_matches, ("pattern",)),
    "metric": (_metric, ("name",)),
}


def load_spec(recipe: Recipe) -> dict[str, Any]:
    path = recipe.path / "evals" / "eval.yaml"
    if not path.is_file():
        raise FileNotFoundError(f"{recipe.id}: evals/eval.yaml is missing")
    spec = miniyaml.load(path)
    if not isinstance(spec, dict) or not isinstance(spec.get("checks"), list) or not spec["checks"]:
        raise ValueError(f"{recipe.id}: evals/eval.yaml needs a non-empty 'checks' list")
    for i, check in enumerate(spec["checks"]):
        if not isinstance(check, dict) or check.get("type") not in CHECKS:
            raise ValueError(f"{recipe.id}: evals/eval.yaml checks[{i}] has an unknown type (known: {', '.join(CHECKS)})")
        for key in CHECKS[check["type"]][1]:
            if key not in check:
                raise ValueError(f"{recipe.id}: evals/eval.yaml checks[{i}] ({check['type']}) needs {key!r}")
    return spec


def run(recipe: Recipe, evidence_dir: Path | None = None) -> list[CheckResult]:
    """Run the recipe's checks against ``evidence_dir`` (default: the golden fixture)."""
    spec = load_spec(recipe)
    if evidence_dir is None:
        evidence_dir = recipe.path / "evals" / str(spec.get("fixture", "fixtures/golden"))
    results: list[CheckResult] = []
    try:
        data = evidence_mod.load(evidence_dir)
    except (FileNotFoundError, ValueError) as exc:
        return [CheckResult("evidence_present", False, str(exc))]
    gated = evidence_mod.gate(data, evidence_dir)
    results.append(CheckResult("evidence_schema", gated.ok, "; ".join(gated.schema_errors)))
    if not gated.ok:
        return results
    results.append(CheckResult("evidence_recipe", gated.evidence["recipe"] == recipe.id, f"evidence.recipe={gated.evidence['recipe']!r}"))
    report_md = report.render_markdown(report.build({"recipe": recipe.id, "id": "eval"}, gated))
    ctx = _Context(gated, evidence_dir, report_md)
    for check in spec["checks"]:
        func = CHECKS[check["type"]][0]
        passed, detail = func(ctx, check)
        label = check["type"] + "".join(f" {k}={v}" for k, v in check.items() if k != "type")
        results.append(CheckResult(label, passed, detail))
    return results
