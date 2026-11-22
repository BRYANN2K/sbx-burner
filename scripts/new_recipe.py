#!/usr/bin/env python3
"""Scaffold a recipe from template/: python3 scripts/new_recipe.py <category> <name>."""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lab.recipe import CATEGORIES, NAME_RE  # noqa: E402

TEXT_SUFFIXES = {".md", ".yaml", ".yml", ".py", ".sh", ".json", ".txt"}


def scaffold(category: str, name: str, root: Path = ROOT) -> Path:
    if category not in CATEGORIES:
        raise SystemExit(f"unknown category {category!r}; choose one of: {', '.join(CATEGORIES)}")
    if not NAME_RE.match(name):
        raise SystemExit(f"name {name!r} must be lowercase kebab-case")
    dest = root / "recipes" / category / name
    if dest.exists():
        raise SystemExit(f"{dest} already exists")
    shutil.copytree(ROOT / "template", dest)
    for path in sorted(dest.rglob("*"), reverse=True):
        if path.is_file() and path.suffix in TEXT_SUFFIXES:
            text = path.read_text(encoding="utf-8")
            text = text.replace("__NAME__", name).replace("__CATEGORY__", category)
            # The installer helper is two directories further away once scaffolded.
            text = text.replace("source=../../kits/lab-tools/", "source=../../../../kits/lab-tools/")
            path.write_text(text, encoding="utf-8")
        if "__NAME__" in path.name:
            path.rename(path.with_name(path.name.replace("__NAME__", name)))
    return dest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("category")
    parser.add_argument("name")
    args = parser.parse_args(argv)
    dest = scaffold(args.category, args.name)
    print(f"created {dest.relative_to(ROOT)}")
    print(f"next: edit the files, then run: python3 -m lab lint {args.category}/{args.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
