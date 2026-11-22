"""Recipe loading and the recipe contract.

A recipe is a directory ``recipes/<category>/<name>/``. The contract below is
shared with the documentation; ``python -m lab lint`` enforces it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import miniyaml

REPO_ROOT = Path(__file__).resolve().parent.parent
RECIPES_DIR = REPO_ROOT / "recipes"
INDEX_FILE = REPO_ROOT / "recipes.yaml"

CATEGORIES = (
    "foundation",
    "pentest",
    "malware",
    "detection",
    "hardening",
    "devsecops",
    "training",
    "ir",
    "ai-security",
    "dev",
    "ci",
    "web",
    "cu",
    "apple",
)
# Recipes in these categories touch targets or hostile material: they never
# run without a scope file.
SCOPE_REQUIRED_CATEGORIES = ("pentest", "malware", "detection", "hardening", "training", "ir", "ai-security")

RISKS = ("low", "medium", "high")
STATUSES = ("ready", "beta", "planned")
SCOPE_MODES = ("required", "optional", "none")
TARGET_MODES = ("required", "optional", "none")
# Kinds a recipe may accept in run.targets: path (mounted dir), repo (cloned
# on the host, then mounted like path), app (a project started inside the
# sandbox), image (docker pull/load), port (the image run as an app on
# localhost), url (a remote app, needs a scope) and demo (the bundled lab
# target via run.demo).
TARGET_KINDS = ("path", "repo", "app", "image", "port", "url", "demo")
FRONTMATTER_KEYS = ("name", "category", "summary", "risk", "time", "variants", "status", "licence", "sources")
# Optional frontmatter: tested_with lists the agents proven by a real run.
# It is information only; every agent the runner knows may run a recipe.
OPTIONAL_FRONTMATTER_KEYS = ("tested_with",)
AGENTS_MD_SECTIONS = ("Role", "Scope rules", "Allowed tools", "Evidence format", "Stop conditions")
FULL_RECIPE_FILES = ("RECIPE.md", "recipe.yaml", "AGENTS.md", "sbxenv.yaml", "run.py")
STUB_RECIPE_FILES = ("RECIPE.md", "recipe.yaml")
NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class RecipeError(ValueError):
    pass


@dataclass
class Recipe:
    path: Path
    meta: dict[str, Any]
    config: dict[str, Any]
    body: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def category(self) -> str:
        return self.path.parent.name

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def id(self) -> str:
        return f"{self.category}/{self.name}"

    @property
    def status(self) -> str:
        return str(self.meta.get("status", ""))

    @property
    def is_stub(self) -> bool:
        return self.status == "planned"

    @property
    def linux(self) -> dict[str, Any]:
        return ((self.config.get("variants") or {}).get("linux")) or {}

    @property
    def macos(self) -> dict[str, Any]:
        return ((self.config.get("variants") or {}).get("macos")) or {}

    @property
    def run(self) -> dict[str, Any]:
        return self.config.get("run") or {}

    @property
    def scope_mode(self) -> str:
        return str(self.config.get("scope", "none"))

    @property
    def target_mode(self) -> str:
        return str(self.run.get("target", "none"))

    @property
    def targets(self) -> list[str]:
        """Target kinds the recipe accepts; defaults keep old recipes working."""
        declared = self.run.get("targets")
        if declared is None:
            return ["path"] if self.target_mode != "none" else []
        return list(declared)

    @property
    def demo(self) -> str | None:
        """Script that starts the bundled demo target, run only with --demo."""
        value = self.run.get("demo")
        return str(value) if value else None

    @property
    def target_health(self) -> str:
        """HTTP path polled after --target-port starts the user's container."""
        return str(self.run.get("target_health") or "/")

    @property
    def kits(self) -> list[str]:
        kit = self.linux.get("kit")
        if not kit:
            return []
        return [kit] if isinstance(kit, str) else list(kit)

    @property
    def network_allow(self) -> list[str]:
        return list((self.run.get("network") or {}).get("allow") or [])

    @property
    def install_allow(self) -> list[str]:
        """Hosts needed only while tools install; closed before the agent starts."""
        return list((self.run.get("network") or {}).get("install_allow") or [])

    def skills(self) -> list[Path]:
        return sorted(p.parent for p in (self.path / "skills").glob("*/SKILL.md"))


def load(path: Path) -> Recipe:
    """Load one recipe directory. Parse problems are collected in ``errors``."""
    errors: list[str] = []
    meta: dict[str, Any] = {}
    config: dict[str, Any] = {}
    body = ""
    recipe_md = path / "RECIPE.md"
    if recipe_md.is_file():
        try:
            meta, body = miniyaml.split_frontmatter(recipe_md.read_text(encoding="utf-8"))
        except miniyaml.YAMLError as exc:
            errors.append(f"RECIPE.md: {exc}")
    recipe_yaml = path / "recipe.yaml"
    if recipe_yaml.is_file():
        try:
            loaded = miniyaml.load(recipe_yaml)
            if isinstance(loaded, dict):
                config = loaded
            else:
                errors.append("recipe.yaml: must be a mapping")
        except miniyaml.YAMLError as exc:
            errors.append(f"recipe.yaml: {exc}")
    return Recipe(path=path, meta=meta, config=config, body=body, errors=errors)


def discover(root: Path | None = None) -> list[Recipe]:
    root = root or RECIPES_DIR
    if not root.is_dir():
        return []
    return [load(p.parent) for p in sorted(root.glob("*/*/RECIPE.md"))]


def find(ref: str, root: Path | None = None) -> Recipe:
    """Resolve ``category/name``, a bare unique ``name`` or a directory path."""
    root = root or RECIPES_DIR
    as_path = Path(ref)
    if (as_path / "recipe.yaml").is_file():
        return load(as_path.resolve())
    if "/" in ref and (root / ref / "recipe.yaml").is_file():
        return load(root / ref)
    matches = [p for p in root.glob(f"*/{ref}") if (p / "recipe.yaml").is_file()]
    if len(matches) == 1:
        return load(matches[0])
    if matches:
        raise RecipeError(f"recipe name {ref!r} is ambiguous: {', '.join(sorted(m.parent.name + '/' + m.name for m in matches))}")
    raise RecipeError(f"recipe not found: {ref!r} (try: python -m lab list)")


def load_index(path: Path | None = None) -> list[dict[str, Any]]:
    path = path or INDEX_FILE
    if not path.is_file():
        return []
    data = miniyaml.load(path) or {}
    entries = data.get("recipes") if isinstance(data, dict) else None
    if entries is None:
        return []
    if not isinstance(entries, list):
        raise RecipeError(f"{path.name}: 'recipes' must be a list")
    return entries
