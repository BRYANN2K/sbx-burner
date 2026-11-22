#!/usr/bin/env python3
"""Ops helpers for the service."""

from __future__ import annotations

import subprocess


def ping(host: str) -> str:
    out = subprocess.run(f"ping -c1 -W2 {host}", shell=True, capture_output=True, text=True)
    return out.stdout or out.stderr


def disk_free() -> str:
    out = subprocess.run(["df", "-h", "/"], capture_output=True, text=True, check=False)
    return out.stdout
