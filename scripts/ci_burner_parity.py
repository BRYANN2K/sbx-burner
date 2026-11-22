#!/usr/bin/env python3
"""Check that `burner run --dry-run` prints the same plan as the engine.

Usage: ci_burner_parity.py <burner binary>

For every runnable recipe and every target kind it declares, run the dry
run through burner and through `python -m lab`, normalise timestamps, and
fail when the outputs differ or either side exits non-zero. Example scopes
get fresh validity dates first, so an expired example cannot make both
sides refuse the same way and pass by accident.
"""

from __future__ import annotations

import datetime as dt
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import os  # noqa: E402
import shutil  # noqa: E402

PLACEHOLDER_IMAGE = "registry.example.invalid/ci/placeholder:1"
TS = re.compile(r"\d{8}-\d{6}")
SANDBOX = re.compile(r"(lab-[a-z0-9-]+)-\d{6}")


FIXTURES = (
    # (category, name, scope, target mode, targets)
    ("devsecops", "fixture-path", "none", "required", "[path]"),
    ("pentest", "fixture-app", "required", "required", "[image, port, url]"),
    ("devsecops", "fixture-optional", "none", "optional", "[path, image]"),
)


def fixture_catalog(dest: Path) -> Path:
    """A copy of the repo with recipes scaffolded from template/, one per
    target-kind mix, for branches that carry no recipes yet."""
    shutil.copytree(ROOT, dest, ignore=shutil.ignore_patterns(".git", "runs", "bin", "__pycache__"))
    for category, name, scope, mode, targets in FIXTURES:
        out = dest / "recipes" / category / name
        shutil.copytree(dest / "template", out)
        for path in out.rglob("*"):
            if path.is_file():
                text = path.read_text().replace("__NAME__", name).replace("__CATEGORY__", category)
                path.write_text(text)
            if "__NAME__" in path.name:
                path.rename(path.with_name(path.name.replace("__NAME__", name)))
        cfg = out / "recipe.yaml"
        text = cfg.read_text()
        text = re.sub(r"^scope: .*$", f"scope: {scope}", text, count=1, flags=re.M)
        text = re.sub(r"^  target: .*$", f"  target: {mode}", text, count=1, flags=re.M)
        text = re.sub(r"^  targets: .*$", f"  targets: {targets}", text, count=1, flags=re.M)
        cfg.write_text(text)
    return dest


def engine_flags(root: Path) -> str:
    out = subprocess.run([sys.executable, "-m", "lab", "run", "--help"], cwd=root, capture_output=True, text=True)
    return out.stdout


def fresh_scope(src: Path, tmp: Path) -> Path:
    today = dt.date.today()
    text = src.read_text()
    text = re.sub(r'(not_before:\s*)"?[0-9-]+"?', rf'\g<1>"{today - dt.timedelta(days=1)}"', text)
    text = re.sub(r'(not_after:\s*)"?[0-9-]+"?', rf'\g<1>"{today + dt.timedelta(days=30)}"', text)
    out = tmp / f"{src.parent.parent.name}-{src.parent.name}-scope.yaml"
    out.write_text(text)
    return out


def first_host(scope: Path) -> str | None:
    m = re.search(r"hosts:\s*\n\s*-\s*([^\s#]+)", scope.read_text())
    return m.group(1) if m else None


def variants(rec, scope: Path | None, supported: str, root: Path) -> list[tuple[str, list[str]]]:
    kinds = rec.targets
    out: list[tuple[str, list[str]]] = []
    if rec.target_mode == "none":
        return [("none", [])]
    if "path" in kinds:
        out.append(("path", ["--target", str(root)]))
    if "image" in kinds:
        args = ["--target-image", PLACEHOLDER_IMAGE]
        out.append(("image", args))
        if "port" in kinds:
            out.append(("image+port", args + ["--target-port", "8080"]))
    if "url" in kinds and scope is not None:
        host = first_host(scope)
        if host:
            out.append(("url", ["--target-url", f"https://{host}"]))
    for kind, flag, value in (("repo", "--target-repo", "BRYANN2K/sbx-burner"), ("app", "--target-app", str(root))):
        if kind in kinds and flag in supported:
            out.append((kind, [flag, value]))
    if rec.target_mode == "optional":
        out.append(("no target", []))
    return out


def norm(text: str) -> str:
    lines = [line for line in text.splitlines() if not line.startswith("catalog: ")]
    return SANDBOX.sub(r"\1-TS", TS.sub("TS", "\n".join(lines)))


def main() -> int:
    burner = sys.argv[1]
    failures = 0
    checked = 0
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        root = ROOT
        if not any((ROOT / "recipes").glob("*/*/recipe.yaml")):
            root = fixture_catalog(tmp / "catalog")
            print(f"no recipes on this branch: using fixture catalog {root}")
        sys.path.insert(0, str(root))
        os.chdir(root)
        from lab import recipe as recipe_mod

        supported = engine_flags(root)
        for rec in recipe_mod.discover(root / "recipes"):
            if rec.is_stub:
                continue
            example = rec.path / "scope.example.yaml"
            scope = fresh_scope(example, tmp) if example.is_file() and rec.scope_mode != "none" else None
            for kind, args in variants(rec, scope, supported, root):
                common = ["--dry-run", "--runs-dir", str(tmp / "runs")] + args
                if scope is not None:
                    common += ["--scope", str(scope)]
                # Same interpreter on both sides: the plan prints its path.
                env = {**os.environ, "BURNER_PYTHON": sys.executable}
                b = subprocess.run(
                    [burner, "--catalog", str(root), "run", rec.id, "--yes"] + common,
                    cwd=tmp,
                    capture_output=True,
                    text=True,
                    env=env,
                )
                e = subprocess.run([sys.executable, "-m", "lab", "run", rec.id] + common, cwd=root, capture_output=True, text=True)
                checked += 1
                bo, eo = norm(b.stdout + b.stderr), norm(e.stdout + e.stderr)
                if b.returncode != 0 or e.returncode != 0 or bo != eo:
                    failures += 1
                    print(f"FAIL {rec.id} [{kind}] burner={b.returncode} engine={e.returncode}")
                    if bo != eo:
                        print("  outputs differ")
                    if e.returncode != 0:
                        print("  engine: " + (e.stderr.strip().splitlines() or ["?"])[-1])
    print(f"parity: {checked} plans checked, {failures} failed")
    return 1 if failures or not checked else 0


if __name__ == "__main__":
    sys.exit(main())
