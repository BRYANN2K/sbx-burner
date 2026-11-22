#!/usr/bin/env python3
"""Print the target flags CI passes to `lab run <recipe> --dry-run`.

Usage: ci_dry_args.py <recipe dir> [scope file]

A recipe that needs a target gets, in this order: `--demo` when it has a
`run.demo`, `--target .` when it accepts a path, a placeholder
`--target-repo` when it accepts a repo, `--target-app .` when it accepts an
app and the repository root has a detectable stack, `--target-url
https://<host>` for the first explicit host of the scope when it accepts a
URL, or a placeholder `--target-image` when it accepts only an image. The
dry run executes nothing, so nothing is cloned, pulled or contacted.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lab import recipe as recipe_mod  # noqa: E402
from lab import scope as scope_mod  # noqa: E402
from lab import sources as sources_mod  # noqa: E402

PLACEHOLDER_IMAGE = "registry.example.invalid/ci/placeholder:1"
PLACEHOLDER_REPO = "https://github.com/example/example.git"


def dry_args(recipe_dir: Path, scope_file: Path | None) -> list[str]:
    rec = recipe_mod.load(recipe_dir)
    if rec.target_mode != "required":
        return []
    kinds = rec.targets
    if rec.demo and "demo" in kinds:
        return ["--demo"]
    if "path" in kinds:
        return ["--target", "."]
    if "repo" in kinds:
        return ["--target-repo", PLACEHOLDER_REPO]
    if "app" in kinds and sources_mod.detect_stack(ROOT):
        return ["--target-app", "."]
    if "url" in kinds and scope_file is not None:
        scope = scope_mod.load(str(scope_file))
        for host in scope.target_hosts:
            if "*" not in host and "/" not in host:
                return ["--target-url", f"https://{host}"]
    if "image" in kinds:
        return ["--target-image", PLACEHOLDER_IMAGE]
    raise SystemExit(f"{rec.id}: no target the CI dry run can pass (declare demo, path, url with a scope host, or image)")


def main(argv: list[str]) -> int:
    if not 1 <= len(argv) <= 2:
        print(__doc__, file=sys.stderr)
        return 2
    print(" ".join(dry_args(Path(argv[0]), Path(argv[1]) if len(argv) == 2 else None)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
