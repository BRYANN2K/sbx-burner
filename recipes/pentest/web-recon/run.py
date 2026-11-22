#!/usr/bin/env python3
"""Run this recipe: python run.py [--scope FILE] [--agent claude|codex] [--target PATH] [--dry-run]."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from lab.cli import recipe_main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(recipe_main(__file__))
