#!/usr/bin/env python3
"""Proving-ground runner.

Dry run is the default: it validates every ``proving-ground/<folder>/``
``target.yaml``/``EXPECTED.yaml`` against the schemas, checks each
``runs[].kind`` against the recipe's declared ``run.targets``, runs any
offline build, and plans each run through ``python3 -m lab run --dry-run``.
A run that needs the output of a build the dry run may not perform (Docker,
network) is planned against a placeholder path instead.

A real run needs ``--real``: it prints the cost estimate, runs builds,
executes ``burner run <recipe> <args> --yes --json`` (or ``python3 -m lab``
without ``--dry-run``), runs the recipe's own eval on each run dir (generic
checks scored, target-specific ones only when EXPECTED.yaml asks), scores the
report and the evidence artifacts against EXPECTED.yaml, and writes redacted
results under ``proving-ground/results/``.

Exit codes: 0 ok; 1 dry-run/validation failure; 2 real run below recall 1.0
or with a precision miss.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PG = Path(__file__).resolve().parent
ROOT = PG.parent
sys.path.insert(0, str(ROOT))

from lab import evals as lab_evals  # noqa: E402
from lab import jsonschema_lite, miniyaml  # noqa: E402
from lab import sbx as lab_sbx  # noqa: E402
from lab.evidence import redact  # noqa: E402
from lab.recipe import RecipeError  # noqa: E402
from lab.recipe import find as find_recipe  # noqa: E402

SCHEMAS = {
    "target": PG / "schema" / "target.schema.json",
    "expected": PG / "schema" / "expected.schema.json",
}
RESULTS_DIR = PG / "results"
# Target args under this prefix are build outputs (see each folder's build.sh).
BUILD_PREFIX = "proving-ground/.build/"
TARBALL_SUFFIXES = (".tar", ".tar.gz", ".tgz")
FINDING_FIELDS = {"rule", "location", "cwe", "target", "title", "severity", "tool"}
# Host tools a build may need while still counting as offline/cheap for --dry-run.
OFFLINE_NEEDS = {"git", "python3", "node", "gcc", "bash"}
# Recipe eval check types that hold for any target. The others (finding
# counts, patterns, metrics) are written for the recipe's own make-target.sh
# target, so they are scored only when EXPECTED.yaml lists them in
# recipe_eval_checks; otherwise their failures are reported as notes.
GENERIC_EVAL_CHECKS = frozenset(
    {"evidence_present", "evidence_schema", "evidence_recipe", "tool_ran", "artifact_exists", "artifact_absent", "no_demotions"}
)
# Very rough model-token cost of one real run, for the --real estimate.
# Note prefix for a folder whose every entry is in runs_pending.
PENDING = "PENDING"
COST_HINT = {"small": "(~50k tokens)", "medium": "(~200k tokens)", "large": "(~600k tokens)"}


def _load_yaml(path: Path) -> tuple[Any, str | None]:
    try:
        return miniyaml.loads(path.read_text()), None
    except (OSError, miniyaml.YAMLError) as exc:
        return None, f"{path.name}: {exc}"


def _validate(data: Any, schema_path: Path) -> list[str]:
    schema = json.loads(schema_path.read_text())
    return jsonschema_lite.validate(data, schema)


def _folders(only: list[str] | None) -> list[Path]:
    names = {o.replace("/", "-") for o in only or []} | set(only or [])
    out = []
    for d in sorted(PG.iterdir()):
        if d.is_dir() and (d / "target.yaml").is_file():
            if not names or d.name in names:
                out.append(d)
    return out


def _recipe_kinds(recipe: str) -> set[str] | None:
    """Declared target kinds, or None when recipe.yaml is absent/unreadable."""
    recipe_yaml = ROOT / "recipes" / recipe / "recipe.yaml"
    if not recipe_yaml.is_file():
        return None
    data, _ = _load_yaml(recipe_yaml)
    run = (data or {}).get("run") or {}
    targets = run.get("targets")
    if isinstance(targets, list):
        return {str(t) for t in targets}
    if run.get("target") in ("required", "optional"):
        return {"path"}
    return set()


def _clean(text: str) -> str:
    """Redact secrets and host paths from anything written to results."""
    text, _ = redact(str(text))
    return text.replace(str(ROOT), "<repo>").replace(str(Path.home()), "~")


def _run(argv: list[str], cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=3600, check=False)


def _fullmatch(pattern: Any, value: Any) -> bool:
    return value is not None and re.fullmatch(str(pattern), str(value), re.S) is not None


def _where(findings: list[dict[str, Any]], where: dict[str, Any]) -> list[dict[str, Any]]:
    return [f for f in findings if all(_fullmatch(pat, f.get(k)) for k, pat in where.items())]


def _artifact_hit(evidence_dirs: list[Path], spec: dict[str, Any]) -> bool:
    """True when a non-empty file under one evidence dir matches path (+ contains)."""
    for base in evidence_dirs:
        for path in sorted(base.glob(spec["path"])):
            if not path.is_file() or path.stat().st_size == 0:
                continue
            pattern = spec.get("contains")
            if pattern is None or re.search(pattern, path.read_text(encoding="utf-8", errors="replace")):
                return True
    return False


def score(
    expected: dict[str, Any],
    findings: list[dict[str, Any]],
    hypotheses: list[dict[str, Any]] | None = None,
    evidence_dirs: list[Path] | None = None,
    eval_failures: list[str] | None = None,
) -> dict[str, Any]:
    """Score a report against EXPECTED.yaml.

    Recall counts must_find (findings), must_hypothesize (hypotheses),
    artifacts (files under the runs' evidence/ dirs) and the recipe's own
    eval: a failed eval is a recall miss.
    """
    hyps = hypotheses or []
    dirs = evidence_dirs or []
    must = [*(expected.get("must_find") or []), *(expected.get("must_hypothesize") or [])]
    hyp_ids = {id(m) for m in expected.get("must_hypothesize") or []}

    def hit(m: dict[str, Any]) -> bool:
        return bool(_where(hyps if id(m) in hyp_ids else findings, m.get("where") or {}))

    arts = expected.get("artifacts") or []
    matched = [m for m in must if hit(m)] + [{"id_hint": f"artifact {a['path']}", **a} for a in arts if _artifact_hit(dirs, a)]
    missed = [m for m in must if not hit(m)] + [{"id_hint": f"artifact {a['path']}", **a} for a in arts if not _artifact_hit(dirs, a)]
    missed += [{"id_hint": "recipe eval", "class": failure} for failure in eval_failures or []]
    leaks = [n for n in (expected.get("must_not_find") or []) if _where(findings, n.get("where") or {})]
    total = len(findings)
    lo = expected.get("min_findings")
    hi = expected.get("max_findings")
    counts_ok = (lo is None or total >= lo) and (hi is None or total <= hi)
    return {
        "recall": (len(matched) / (len(matched) + len(missed))) if (matched or missed) else 1.0,
        "matched": matched,
        "missed": missed,
        "precision_misses": leaks,
        "total": total,
        "counts_ok": counts_ok,
        "ok": not missed and not leaks and counts_ok,
    }


def _lab_plan_argv(recipe: str, entry: dict[str, Any], folder: Path, agent: str | None) -> list[str]:
    argv = [sys.executable, "-m", "lab", "run", recipe, *entry["args"]]
    scope = folder / "scope.yaml"
    if scope.is_file():
        argv += ["--scope", str(scope.relative_to(ROOT))]
    if agent:
        argv += ["--agent", agent]
    return argv + ["--dry-run"]


def _real_argv(runner: str, recipe: str, entry: dict[str, Any], folder: Path, agent: str | None) -> list[str]:
    base = ["burner"] if runner == "burner" else [sys.executable, "-m", "lab"]
    argv = [*base, "run", recipe, *entry["args"]]
    scope = folder / "scope.yaml"
    if scope.is_file():
        argv += ["--scope", str(scope.relative_to(ROOT))]
    if agent:
        argv += ["--agent", agent]
    return argv + (["--yes", "--json"] if runner == "burner" else [])


def _placeholder_args(args: list[str], tmp: Path) -> list[str]:
    """Swap build outputs for empty placeholders, so the dry run can plan them."""
    out = []
    for arg in args:
        if not arg.startswith(BUILD_PREFIX):
            out.append(arg)
            continue
        path = tmp / arg[len(BUILD_PREFIX) :]
        if arg.endswith(TARBALL_SUFFIXES):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        else:
            path.mkdir(parents=True, exist_ok=True)
        out.append(str(path))
    return out


def _build_allowed_offline(target: dict[str, Any]) -> bool:
    return set(target.get("needs") or []) <= OFFLINE_NEEDS


def _binding_env(tmp: Path) -> dict[str, str] | None:
    """Throwaway ``XDG_CONFIG_HOME`` approving every kit's credential domains.

    Dry-run planning refuses a mixin workload whose binding is missing from
    credentials.yaml (it is how the TUI offers the approval prompt). In the
    harness the approval state is irrelevant — CI stores no secrets and the
    file only names domains — so the dry run plans against a fixture binding
    generated from the kits. Real runs are untouched: they still refuse
    until a human approves through ``burner approve``.
    """
    needs = lab_sbx.kits_binding_needs(ROOT / "kits")
    if not needs:
        return None
    xdg = tmp / "xdg"
    creds = xdg / "sbx" / "credentials.yaml"
    creds.parent.mkdir(parents=True)
    creds.write_text(lab_sbx.binding_snippet(needs) + "\n")
    env = dict(os.environ)
    env["XDG_CONFIG_HOME"] = str(xdg)
    return env


def _run_build(folder: Path, target: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    build_dir = PG / ".build" / folder.name
    build_dir.mkdir(parents=True, exist_ok=True)
    env["PG_BUILD"] = str(build_dir)
    env["PG_FOLDER"] = str(folder)
    return _run(["bash", str(folder / target["build"])], cwd=folder, env=env)


def _find_report(stdout: str, since: float) -> Path | None:
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        for key in ("report", "report_path", "run_dir"):
            if isinstance(data, dict) and isinstance(data.get(key), str):
                p = Path(data[key])
                cand = p if p.name == "report.json" else p / "report.json"
                if cand.is_file():
                    return cand
    runs = ROOT / "runs"
    if runs.is_dir():
        cands = [p for p in runs.glob("*/report.json") if p.stat().st_mtime >= since]
        if cands:
            return max(cands, key=lambda p: p.stat().st_mtime)
    return None


def _write_results(date: str, slug: str, recipe: str, verdict: dict[str, Any]) -> Path:
    RESULTS_DIR.mkdir(exist_ok=True)
    lines = [f"# proving-ground: {recipe} ({date})", ""]
    for m in verdict["matched"]:
        lines.append(f"- PASS expected `{_clean(m.get('id_hint') or m.get('class') or '?')}`")
    for m in verdict["missed"]:
        detail = f" ({_clean(m['class'])})" if m.get("class") else ""
        lines.append(f"- MISS expected `{_clean(m.get('id_hint') or '?')}`{detail}")
    for n in verdict["precision_misses"]:
        lines.append(f"- PRECISION MISS `{_clean(n.get('reason') or '?')}`")
    for note in verdict.get("eval_notes") or []:
        lines.append(f"- NOTE recipe eval, not scored for this target: `{_clean(note)}`")
    lines += [
        "",
        f"findings={verdict['total']} recall={verdict['recall']:.2f} "
        f"counts_ok={verdict['counts_ok']} verdict={'PASS' if verdict['ok'] else 'FAIL'}",
        "",
    ]
    path = RESULTS_DIR / f"{date}-{slug}.md"
    path.write_text("\n".join(lines))
    return path


def _write_summary(date: str, rows: list[tuple[str, dict[str, Any]]]) -> Path:
    RESULTS_DIR.mkdir(exist_ok=True)
    lines = [
        f"# proving-ground results {date}",
        "",
        "| recipe | recall | precision | findings | verdict |",
        "| --- | --- | --- | --- | --- |",
    ]
    for recipe, v in rows:
        prec = "miss" if v["precision_misses"] else "ok"
        lines.append(f"| {recipe} | {v['recall']:.2f} | {prec} | {v['total']} | {'PASS' if v['ok'] else 'FAIL'} |")
    path = RESULTS_DIR / f"{date}.md"
    path.write_text("\n".join(lines) + "\n")
    return path


# Target directories handed to the agent must not carry the answers.
_ANSWER_FILES = ("EXPECTED.yaml", "target.yaml")
_ANSWER_MARKERS = ("Planted issues", "must NOT be reported", "must_find", "must_not_find")
_PATH_FLAGS = ("--target", "--target-app")


def _answer_leaks(entry_args: list[str]) -> list[str]:
    """Paths given to the agent (--target, --target-app) that hold answer material."""
    leaks: list[str] = []
    for i, arg in enumerate(entry_args[:-1]):
        if arg not in _PATH_FLAGS:
            continue
        path = Path(entry_args[i + 1])
        path = path if path.is_absolute() else ROOT / path
        if not path.exists():
            continue
        files = [path] if path.is_file() else [p for p in path.rglob("*") if p.is_file() and "node_modules" not in p.parts]
        for f in files:
            if f.name in _ANSWER_FILES:
                leaks.append(str(f.relative_to(ROOT) if f.is_relative_to(ROOT) else f))
            elif f.suffix.lower() in (".md", ".txt", ".rst"):
                text = f.read_text(encoding="utf-8", errors="replace")
                if any(m in text for m in _ANSWER_MARKERS):
                    leaks.append(str(f.relative_to(ROOT) if f.is_relative_to(ROOT) else f))
    return leaks


def _check_folder(folder: Path, args: argparse.Namespace) -> tuple[bool, str]:
    """Validate one folder and lab-dry-run its plans. Returns (ok, note)."""
    target, err = _load_yaml(folder / "target.yaml")
    if err:
        return False, err
    errors = _validate(target, SCHEMAS["target"])
    exp_path = folder / "EXPECTED.yaml"
    expected, err = _load_yaml(exp_path)
    if err:
        return False, err
    errors += _validate(expected, SCHEMAS["expected"])
    if errors:
        return False, "; ".join(errors)
    recipe = target["recipe"]
    if expected.get("recipe") != recipe:
        return False, "EXPECTED.yaml recipe differs from target.yaml"
    if folder.name != recipe.replace("/", "-"):
        return False, f"folder name {folder.name} does not match recipe {recipe}"
    if not (ROOT / "recipes" / recipe).is_dir():
        return True, "SKIP (recipe not on this branch)"
    kinds = _recipe_kinds(recipe)
    if kinds is None:
        return False, "recipe directory exists but recipe.yaml is missing or unreadable"
    bad = [r["kind"] for r in target.get("runs") or [] if r["kind"] not in kinds]
    if bad:
        return False, f"kinds not in recipe run.targets: {sorted(set(bad))}"
    if not (target.get("runs") or target.get("runs_pending")):
        return False, "no runs or runs_pending entries"
    if not target.get("runs"):
        return True, f"{PENDING}: {len(target['runs_pending'])} runs_pending entries, nothing to run yet"
    for entry in target.get("runs") or []:
        leaks = _answer_leaks(entry["args"])
        if leaks:
            return False, f"kind {entry['kind']} hands the agent answer material: {', '.join(sorted(leaks)[:5])}"
    placeholders = False
    if "build" in target:
        if _build_allowed_offline(target):
            proc = _run_build(folder, target)
            if proc.returncode != 0:
                return False, f"build failed: {proc.stderr.strip()[-300:]}"
        else:
            print(f"  {folder.name}: would run {target['build']} (needs: {', '.join(target.get('needs') or [])})")
            placeholders = True
    with tempfile.TemporaryDirectory(prefix="pg-placeholder-") as tmp:
        env = _binding_env(Path(tmp))
        for entry in target.get("runs") or []:
            entry_args = _placeholder_args(entry["args"], Path(tmp)) if placeholders else entry["args"]
            proc = _run(_lab_plan_argv(recipe, {**entry, "args": entry_args}, folder, args.agent), cwd=ROOT, env=env)
            if proc.returncode != 0:
                tail = (proc.stdout + proc.stderr).strip()[-400:]
                return False, f"lab --dry-run failed for kind {entry['kind']}: {tail}"
    n_runs = len(target.get("runs") or [])
    n_pending = len(target.get("runs_pending") or [])
    note = f"{n_runs} run(s) planned ok" + (f", {n_pending} pending" if n_pending else "")
    return True, note + (" (build outputs as placeholders)" if placeholders else "")


def recipe_eval(recipe: str, run_dir: Path, extra: list[str] | None = None) -> tuple[list[str], list[str]]:
    """Run the recipe's own eval on a real run dir.

    Returns (scored failures, unscored failures). Generic check types are
    always scored; ``extra`` adds types, or ``["all"]`` scores every check.
    """
    scored = GENERIC_EVAL_CHECKS | set(extra or [])
    try:
        results = lab_evals.run(find_recipe(recipe, ROOT / "recipes"), run_dir / "workspace" / "evidence")
    except (RecipeError, FileNotFoundError, ValueError) as exc:
        return [_clean(str(exc))], []
    bad = [(r.check.split(" ", 1)[0], _clean(f"{r.check} [{r.detail}]")) for r in results if not r.passed]
    if "all" in scored:
        return [text for _, text in bad], []
    return [text for kind, text in bad if kind in scored], [text for kind, text in bad if kind not in scored]


def _real_folder(folder: Path, args: argparse.Namespace) -> dict[str, Any]:
    target = miniyaml.loads((folder / "target.yaml").read_text())
    expected = miniyaml.loads((folder / "EXPECTED.yaml").read_text())
    recipe = target["recipe"]
    if "build" in target:
        proc = _run_build(folder, target)
        if proc.returncode != 0:
            return {
                "recipe": recipe,
                "error": f"build failed: {proc.stderr.strip()[-300:]}",
                "ok": False,
                "recall": 0.0,
                "matched": [],
                "missed": expected.get("must_find") or [],
                "precision_misses": [],
                "total": 0,
                "counts_ok": False,
            }
    since = datetime.now(tz=UTC).timestamp()
    all_findings: list[dict[str, Any]] = []
    all_hyps: list[dict[str, Any]] = []
    evidence_dirs: list[Path] = []
    eval_failures: list[str] = []
    eval_notes: list[str] = []
    for entry in target.get("runs") or []:
        leaks = _answer_leaks(entry["args"])
        if leaks:
            where = ", ".join(sorted(leaks)[:5])
            return {"recipe": recipe, "error": f"refused: kind {entry['kind']} hands the agent answer material: {where}", "ok": False}
        proc = _run(_real_argv(args.runner, recipe, entry, folder, args.agent), cwd=ROOT)
        report = _find_report(proc.stdout, since)
        if proc.returncode != 0 or report is None:
            tail = (proc.stdout + proc.stderr).strip()[-400:]
            return {
                "recipe": recipe,
                "error": f"run failed: {tail}",
                "ok": False,
                "recall": 0.0,
                "matched": [],
                "missed": expected.get("must_find") or [],
                "precision_misses": [],
                "total": 0,
                "counts_ok": False,
            }
        data = json.loads(report.read_text())
        all_findings += data.get("findings") or []
        all_hyps += data.get("hypotheses") or []
        evidence_dirs.append(report.parent / "workspace" / "evidence")
        failures, notes = recipe_eval(recipe, report.parent, expected.get("recipe_eval_checks"))
        eval_failures += [f"{entry['kind']}: {text}" for text in failures]
        eval_notes += [f"{entry['kind']}: {text}" for text in notes]
    verdict = score(expected, all_findings, all_hyps, evidence_dirs, eval_failures)
    verdict["recipe"] = recipe
    verdict["eval_notes"] = eval_notes
    return verdict


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--only", nargs="+", metavar="RECIPE", help="limit to these recipes or folder names")
    p.add_argument("--real", action="store_true", help="perform real burner runs (spends model tokens)")
    p.add_argument("--dry-run", action="store_true", help="explicit dry run (the default)")
    p.add_argument("--runner", choices=["burner", "lab"], help="runner for --real (default: burner on PATH, else lab)")
    p.add_argument("--agent", choices=["claude", "codex"], help="agent passed to the runner")
    p.add_argument("--yes", action="store_true", help="skip the --real confirmation prompt")
    p.add_argument("--json", action="store_true", help="print the outcome as JSON")
    args = p.parse_args(argv)

    folders = _folders(args.only)
    if args.only and not folders:
        print(f"no proving-ground folder matches: {' '.join(args.only)}", file=sys.stderr)
        return 1
    if not folders:
        print("no proving-ground folders found", file=sys.stderr)
        return 1

    if not args.real:
        ok = True
        for folder in folders:
            good, note = _check_folder(folder, args)
            ok = ok and good
            label = "FAIL" if not good else ("PENDING" if note.startswith(PENDING) else "OK")
            print(f"{label} {folder.name}: {note.removeprefix(PENDING + ': ')}")
        if args.json:
            print(json.dumps({"mode": "dry-run", "ok": ok}))
        return 0 if ok else 1

    args.runner = args.runner or ("burner" if shutil.which("burner") else "lab")
    costs = {f.name: (miniyaml.loads((f / "target.yaml").read_text()).get("cost") or "?") for f in folders}
    print("cost estimate per recipe (very rough model tokens):")
    for name, cost in costs.items():
        print(f"  {name}: {cost} {COST_HINT.get(cost, '')}")
    if not args.yes:
        try:
            if input("run these recipes for real? [y/N] ").strip().lower() not in ("y", "yes"):
                print("aborted", file=sys.stderr)
                return 1
        except EOFError:
            print("no terminal to confirm; pass --yes", file=sys.stderr)
            return 1
    date = datetime.now(tz=UTC).strftime("%Y-%m-%d")
    rows: list[tuple[str, dict[str, Any]]] = []
    worst = 0
    for folder in folders:
        if not miniyaml.loads((folder / "target.yaml").read_text()).get("runs"):
            print(f"PENDING {folder.name}: only runs_pending entries, not run")
            continue
        verdict = _real_folder(folder, args)
        recipe = verdict["recipe"]
        if "error" in verdict:
            print(f"FAIL {folder.name}: {verdict['error']}")
            worst = 1
        else:
            path = _write_results(date, folder.name, recipe, verdict)
            print(f"{'PASS' if verdict['ok'] else 'FAIL'} {folder.name} -> {path.relative_to(ROOT)}")
            if not verdict["ok"]:
                worst = 2
        rows.append((recipe, verdict))
    summary = _write_summary(date, rows)
    print(f"summary -> {summary.relative_to(ROOT)}")
    if args.json:
        print(json.dumps({r: {"recall": v["recall"], "ok": v["ok"]} for r, v in rows}))
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
