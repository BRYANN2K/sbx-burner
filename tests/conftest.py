from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from lab import miniyaml, recipe  # noqa: E402


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A throwaway repository root with kits/, skills/ and an empty index."""
    import shutil

    shutil.copytree(ROOT / "kits", tmp_path / "kits")
    shutil.copytree(ROOT / "skills", tmp_path / "skills")
    shutil.copytree(ROOT / "template", tmp_path / "template")
    (tmp_path / "recipes").mkdir()
    (tmp_path / "recipes.yaml").write_text("recipes: []\n", encoding="utf-8")
    return tmp_path


@pytest.fixture
def make_recipe(repo: Path):
    """Scaffold the template into the throwaway repo and index it."""
    import new_recipe

    def _make(category: str = "devsecops", name: str = "demo", **overrides: str) -> recipe.Recipe:
        dest = new_recipe.scaffold(category, name, root=repo)
        for rel, (old, new) in overrides.items():
            path = dest / rel
            text = path.read_text(encoding="utf-8")
            assert old in text, f"{old!r} not in {rel}"
            path.write_text(text.replace(old, new), encoding="utf-8")
        loaded = recipe.load(dest)
        entries = (repo / "recipes.yaml").read_text(encoding="utf-8")
        if entries.strip() == "recipes: []":
            entries = "recipes:\n"
        entries += (
            f"  - path: recipes/{category}/{name}\n    name: {name}\n    category: {category}\n"
            f"    summary: {loaded.meta['summary']}\n    risk: {loaded.meta['risk']}\n    status: {loaded.meta['status']}\n"
            "    variants: {linux: beta, macos: planned}\n"
        )
        (repo / "recipes.yaml").write_text(entries, encoding="utf-8")
        assert miniyaml.load(repo / "recipes.yaml")
        return loaded

    return _make


SCOPE_OK = """\
schema_version: "1"
id: unit-lab
owner: Test Owner
authorization:
  type: own-lab
valid:
  not_before: "2026-01-01"
  not_after: "2026-12-31"
targets:
  - name: juice
    hosts: [juice.lab.internal:3000, 10.0.5.0/24]
network:
  mode: strict
  allow: [mirror.lab.internal]
  deny: [10.0.5.9]
techniques:
  allowed: [recon, scan]
  forbidden: [exploit]
"""


@pytest.fixture
def scope_file(tmp_path: Path) -> Path:
    path = tmp_path / "scope.yaml"
    path.write_text(SCOPE_OK, encoding="utf-8")
    return path
