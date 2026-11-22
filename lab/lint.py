"""recipe-lint: validate every recipe against the recipe contract."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from . import evals, miniyaml, scope
from .recipe import (
    AGENTS_MD_SECTIONS,
    CATEGORIES,
    FRONTMATTER_KEYS,
    FULL_RECIPE_FILES,
    NAME_RE,
    REPO_ROOT,
    RISKS,
    SCOPE_MODES,
    SCOPE_REQUIRED_CATEGORIES,
    STATUSES,
    STUB_RECIPE_FILES,
    TARGET_KINDS,
    TARGET_MODES,
    Recipe,
    discover,
    load_index,
)
from .sbx import AGENTS

INDEX_KEYS = ("path", "name", "category", "summary", "risk", "status")
# Material that may be linked but never copied into the repository.
LINK_ONLY = ("trailofbits/skills", "book.hacktricks", "semgrep-rules")
# Every declared target kind must be referenced by the agent prompt: the env
# var the runner exports, or the mount path for a path target.
KIND_NEEDLES = {
    "path": ("LAB_TARGET_PATH", "/home/agent/target"),
    "repo": ("LAB_TARGET_PATH", "/home/agent/target"),
    "app": ("LAB_TARGET_URL",),
    "image": ("LAB_TARGET_IMAGE",),
    "port": ("LAB_TARGET_URL",),
    "url": ("LAB_TARGET_URL",),
    "demo": ("LAB_DEMO",),
}


def _list_of_str(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(v, str) and v for v in value)


def lint_recipe(recipe: Recipe, repo_root: Path = REPO_ROOT) -> list[str]:
    errors = list(recipe.errors)
    path = recipe.path
    meta, config = recipe.meta, recipe.config

    if recipe.category not in CATEGORIES:
        errors.append(f"category directory {recipe.category!r} is not one of {', '.join(CATEGORIES)}")
    if not NAME_RE.match(recipe.name):
        errors.append(f"directory name {recipe.name!r} must be lowercase kebab-case")

    # --- RECIPE.md frontmatter -------------------------------------------
    for key in FRONTMATTER_KEYS:
        if key not in meta or meta[key] in (None, "", []):
            errors.append(f"RECIPE.md: frontmatter key {key!r} is missing or empty")
    if meta.get("name") not in (None, recipe.name):
        errors.append(f"RECIPE.md: name {meta.get('name')!r} must match the directory {recipe.name!r}")
    if meta.get("category") not in (None, recipe.category):
        errors.append(f"RECIPE.md: category {meta.get('category')!r} must match the directory {recipe.category!r}")
    if "risk" in meta and meta["risk"] not in RISKS:
        errors.append(f"RECIPE.md: risk must be one of {', '.join(RISKS)}")
    if "status" in meta and meta["status"] not in STATUSES:
        errors.append(f"RECIPE.md: status must be one of {', '.join(STATUSES)}")
    if "summary" in meta and isinstance(meta["summary"], str) and len(meta["summary"]) > 160:
        errors.append("RECIPE.md: summary is longer than 160 characters")
    if "agents" in meta:
        if not _list_of_str(meta["agents"]):
            errors.append("RECIPE.md: agents must be a non-empty list")
        else:
            for agent in meta["agents"]:
                if agent not in AGENTS:
                    errors.append(f"RECIPE.md: unknown agent {agent!r} (known: {', '.join(AGENTS)})")
    variants_meta = meta.get("variants")
    if "variants" in meta and not (isinstance(variants_meta, dict) and {"linux", "macos"} <= set(variants_meta)):
        errors.append("RECIPE.md: variants must map both 'linux' and 'macos' to a status")
    elif isinstance(variants_meta, dict):
        for name, status in variants_meta.items():
            if status not in STATUSES + ("n/a",):
                errors.append(f"RECIPE.md: variants.{name} must be one of {', '.join(STATUSES)} or n/a")
    if "sources" in meta and not isinstance(meta["sources"], list):
        errors.append("RECIPE.md: sources must be a list")

    # --- recipe.yaml ------------------------------------------------------
    if config.get("schema_version") != "1":
        errors.append('recipe.yaml: schema_version must be "1"')
    if config.get("name") != recipe.name:
        errors.append("recipe.yaml: name must match the directory")
    if config.get("category") != recipe.category:
        errors.append("recipe.yaml: category must match the directory")
    if config.get("scope") not in SCOPE_MODES:
        errors.append(f"recipe.yaml: scope must be one of {', '.join(SCOPE_MODES)}")
    variants = config.get("variants")
    if not isinstance(variants, dict) or "linux" not in variants or "macos" not in variants:
        errors.append("recipe.yaml: variants must define 'linux' and 'macos'")
        variants = {}
    for vname in ("linux", "macos"):
        variant = variants.get(vname)
        if variant is None:
            continue
        if not isinstance(variant, dict) or variant.get("status") not in STATUSES + ("n/a",):
            errors.append(f"recipe.yaml: variants.{vname}.status must be one of {', '.join(STATUSES)} or n/a")
        elif isinstance(variants_meta, dict) and variants_meta.get(vname) != variant.get("status"):
            errors.append(f"recipe.yaml: variants.{vname}.status differs from RECIPE.md")

    required_files = STUB_RECIPE_FILES if recipe.is_stub else FULL_RECIPE_FILES
    for name in required_files:
        if not (path / name).is_file():
            errors.append(f"missing file: {name}")
    if recipe.is_stub:
        return errors

    # --- linux variant ----------------------------------------------------
    linux = recipe.linux
    if linux.get("status") in ("ready", "beta"):
        for key in ("kit", "image", "sbxenv"):
            if not linux.get(key):
                errors.append(f"recipe.yaml: variants.linux.{key} is required")
        for kit in recipe.kits + ([linux["workload"]] if linux.get("workload") else []):
            kit_dir = repo_root / kit
            stem = kit_dir.name
            if not (kit_dir / f"{stem}.yaml").is_file():
                errors.append(f"recipe.yaml: kit {kit!r} has no descriptor {stem}.yaml")
        if linux.get("sbxenv"):
            sbxenv_path = path / str(linux["sbxenv"])
            if not sbxenv_path.is_file():
                errors.append(f"recipe.yaml: sbxenv file {linux['sbxenv']!r} not found")
            else:
                try:
                    env = miniyaml.load(sbxenv_path) or {}
                    if env.get("schemaVersion") != "1":
                        errors.append('sbxenv.yaml: schemaVersion must be "1"')
                    if not env.get("agent"):
                        errors.append("sbxenv.yaml: agent is required")
                except miniyaml.YAMLError as exc:
                    errors.append(f"sbxenv.yaml: {exc}")

    # --- run block --------------------------------------------------------
    run = recipe.run
    target_mode = str(run.get("target", "none"))
    if target_mode not in TARGET_MODES:
        errors.append(f"recipe.yaml: run.target must be one of {', '.join(TARGET_MODES)}")
    declared = run.get("targets")
    if declared is not None:
        if not isinstance(declared, list) or any(k not in TARGET_KINDS for k in declared):
            errors.append(f"recipe.yaml: run.targets must be a list drawn from {', '.join(TARGET_KINDS)}")
            declared = None
        else:
            if "port" in declared and "image" not in declared:
                errors.append("recipe.yaml: run.targets 'port' requires 'image'")
            if "demo" in declared and not run.get("demo"):
                errors.append("recipe.yaml: run.targets 'demo' requires run.demo")
    if target_mode == "none" and declared:
        errors.append("recipe.yaml: run.target 'none' cannot declare run.targets")
    if target_mode in ("required", "optional") and declared == [] and not run.get("demo"):
        errors.append("recipe.yaml: a recipe that accepts no target kind cannot have run.target required/optional")
    if run.get("demo"):
        if not (path / str(run["demo"])).is_file():
            errors.append(f"recipe.yaml: run.demo {run['demo']!r} not found in the recipe directory")
        if "demo" not in recipe.targets:
            errors.append("recipe.yaml: run.demo is set but 'demo' is not in run.targets")
    health = run.get("target_health")
    if health is not None and not str(health).startswith("/"):
        errors.append("recipe.yaml: run.target_health must start with '/'")
    timeout = run.get("timeout_minutes")
    if not isinstance(timeout, int) or not 1 <= timeout <= 480:
        errors.append("recipe.yaml: run.timeout_minutes must be an integer between 1 and 480")
    for key, hosts in (("allow", recipe.network_allow), ("install_allow", recipe.install_allow)):
        for host in hosts:
            host_errors: list[str] = []
            scope._check_host(host, f"run.network.{key}", host_errors)
            errors.extend(f"recipe.yaml: {e}" for e in host_errors)
    for skill in run.get("shared_skills") or []:
        if not (repo_root / "skills" / skill / "SKILL.md").is_file():
            errors.append(f"recipe.yaml: shared skill {skill!r} not found in skills/")

    # --- scope ------------------------------------------------------------
    needs_scope = recipe.category in SCOPE_REQUIRED_CATEGORIES or meta.get("risk") in ("medium", "high")
    if needs_scope and config.get("scope") != "required":
        errors.append("recipe.yaml: scope must be 'required' for security recipes (category or risk medium/high)")
    example = path / "scope.example.yaml"
    if config.get("scope") == "required" and not example.is_file():
        errors.append("missing file: scope.example.yaml (scope is required)")
    if example.is_file():
        try:
            scope.load(example, check_dates=False)
        except scope.ScopeError as exc:
            errors.append(f"scope.example.yaml: {exc}")

    # --- AGENTS.md --------------------------------------------------------
    agents_md = path / "AGENTS.md"
    if agents_md.is_file():
        headings = [h.strip().lower() for h in re.findall(r"^#{1,3}\s+(.+)$", agents_md.read_text(encoding="utf-8"), re.M)]
        for section in AGENTS_MD_SECTIONS:
            if section.lower() not in headings:
                errors.append(f"AGENTS.md: missing section heading {section!r}")

    # --- skills -----------------------------------------------------------
    skills = recipe.skills()
    if not skills and not run.get("shared_skills"):
        errors.append("skills/: needs at least one <skill>/SKILL.md (or run.shared_skills)")
    for skill_dir in skills:
        errors.extend(f"skills/{skill_dir.name}/SKILL.md: {e}" for e in lint_skill(skill_dir))

    # The prompt must teach the agent about each accepted target kind.
    prompt_files = [agents_md] if agents_md.is_file() else []
    prompt_files += [sd / "SKILL.md" for sd in skills]
    prompt_text = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in prompt_files)
    for kind in recipe.targets:
        if kind not in KIND_NEEDLES:
            continue
        if not any(needle in prompt_text for needle in KIND_NEEDLES[kind]):
            errors.append(f"run.targets {kind!r}: AGENTS.md or a SKILL.md must mention {' or '.join(KIND_NEEDLES[kind])}")

    # --- tools ------------------------------------------------------------
    tools_dir = path / "tools"
    tool_files = [p for p in tools_dir.rglob("*") if p.is_file()] if tools_dir.is_dir() else []
    if not tool_files:
        errors.append("tools/: needs at least one file (install script or README explaining why none is needed)")
    for tool in tool_files:
        if tool.suffix == ".sh":
            text = tool.read_text(encoding="utf-8")
            if not text.startswith("#!"):
                errors.append(f"tools/{tool.name}: missing shebang")
            if "set -euo pipefail" not in text:
                errors.append(f"tools/{tool.name}: must use 'set -euo pipefail'")
            if re.search(r"(curl|wget)[^\n|]*\|\s*(sudo\s+)?(ba)?sh", text):
                errors.append(f"tools/{tool.name}: do not pipe a download into a shell; pin and verify instead")

    # --- run.py -----------------------------------------------------------
    run_py = path / "run.py"
    if run_py.is_file() and "recipe_main(__file__" not in run_py.read_text(encoding="utf-8"):
        errors.append("run.py: must call lab.cli.recipe_main")

    # --- evals ------------------------------------------------------------
    try:
        results = evals.run(recipe)
    except (FileNotFoundError, ValueError) as exc:
        errors.append(f"evals: {exc}")
    else:
        for res in results:
            if not res.passed:
                errors.append(f"evals: golden fixture fails check '{res.check}' ({res.detail})")

    # --- licence hygiene --------------------------------------------------
    for md in path.rglob("*.md"):
        text = md.read_text(encoding="utf-8", errors="replace")
        if re.search(r"(?i)vendored from\s+\S*(" + "|".join(re.escape(s) for s in LINK_ONLY) + ")", text):
            errors.append(f"{md.relative_to(path)}: link-only material must not be vendored")
    return errors


def lint_skill(skill_dir: Path) -> list[str]:
    errors: list[str] = []
    try:
        meta, body = miniyaml.split_frontmatter((skill_dir / "SKILL.md").read_text(encoding="utf-8"))
    except miniyaml.YAMLError as exc:
        return [str(exc)]
    if meta.get("name") != skill_dir.name:
        errors.append(f"frontmatter name must be {skill_dir.name!r}")
    description = meta.get("description")
    if not isinstance(description, str) or len(description) < 20:
        errors.append("frontmatter description must say what the skill does and when to use it")
    elif len(description) > 1024:
        errors.append("frontmatter description is longer than 1024 characters")
    if len(body.strip()) < 40:
        errors.append("body is empty")
    return errors


def lint_index(recipes: list[Recipe], repo_root: Path = REPO_ROOT, strict: bool = False) -> list[str]:
    """recipes.yaml entries must agree with each recipe's frontmatter.

    A recipe without an entry is only an error in strict mode: recipe pull
    requests do not touch the index (it would conflict between them); the
    index is synced with ``scripts/gen_index.py --sync``.
    """
    errors: list[str] = []
    try:
        entries = load_index(repo_root / "recipes.yaml")
    except (miniyaml.YAMLError, ValueError) as exc:
        return [f"recipes.yaml: {exc}"]
    by_path: dict[str, dict[str, Any]] = {}
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(f"recipes.yaml: entry {i} must be a mapping")
            continue
        for key in INDEX_KEYS:
            if key not in entry:
                errors.append(f"recipes.yaml: entry {i} is missing {key!r}")
        if entry.get("path") in by_path:
            errors.append(f"recipes.yaml: duplicate entry {entry.get('path')!r}")
        by_path[str(entry.get("path"))] = entry
    known = set()
    for recipe in recipes:
        rel = f"recipes/{recipe.id}"
        known.add(rel)
        entry = by_path.get(rel)
        if entry is None:
            if strict:
                errors.append(f"recipes.yaml: missing entry for {rel} (run: python3 scripts/gen_index.py --sync)")
            continue
        for key in ("name", "category", "summary", "risk", "status"):
            if entry.get(key) != recipe.meta.get(key):
                errors.append(f"recipes.yaml: {rel}: {key} differs from RECIPE.md")
    for rel in by_path:
        if rel not in known:
            errors.append(f"recipes.yaml: entry {rel!r} has no recipe directory")
    return errors


def lint_shared_skills(repo_root: Path = REPO_ROOT) -> list[str]:
    errors: list[str] = []
    for skill_md in sorted((repo_root / "skills").glob("*/SKILL.md")):
        errors.extend(f"skills/{skill_md.parent.name}/SKILL.md: {e}" for e in lint_skill(skill_md.parent))
    return errors


def lint_all(repo_root: Path = REPO_ROOT, strict_index: bool = False) -> dict[str, list[str]]:
    """Return ``{label: [errors]}`` for every recipe plus the index."""
    recipes = discover(repo_root / "recipes")
    report: dict[str, list[str]] = {}
    for recipe in recipes:
        report[recipe.id] = lint_recipe(recipe, repo_root)
    for orphan in sorted((repo_root / "recipes").glob("*/*/")) if (repo_root / "recipes").is_dir() else []:
        if not (orphan / "RECIPE.md").is_file():
            report[f"{orphan.parent.name}/{orphan.name}"] = ["missing file: RECIPE.md"]
    report["recipes.yaml"] = lint_index(recipes, repo_root, strict=strict_index)
    report["skills/"] = lint_shared_skills(repo_root)
    return report
