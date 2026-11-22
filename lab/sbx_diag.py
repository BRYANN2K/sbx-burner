"""Why an sbx step failed, when sbx itself only says "failed to run sandbox container".

Reads the sbx daemon log (and the failed container's own log) for ERROR
lines about one sandbox. Best effort: size-capped, sanitized, and never
raises; the run goes on whatever happens here.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
from pathlib import Path

from . import sanitize

DAEMON_TAIL = 4 << 20  # bytes of daemon.log read from the end
CONTAINER_TAIL = 64 << 10
MAX_LINES = 5
_CONTAINER_ID = re.compile(r"containers/([0-9a-f]{64})")


def state_dir() -> Path | None:
    """sbx's daemon state folder ($LAB_SBX_STATE_DIR overrides)."""
    env = os.environ.get("LAB_SBX_STATE_DIR")
    if env:
        return Path(env)
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "com.docker.sandboxes" / "sandboxes" / "sandboxd"
    return None  # TODO(verify): sbx's state folder on Linux


def _tail(path: Path, limit: int) -> str:
    try:
        if not path.is_file() or path.is_symlink():
            return ""
        with path.open("rb") as fh:
            size = path.stat().st_size
            if size > limit:
                fh.seek(size - limit)
            return fh.read(limit).decode("utf-8", errors="replace")
    except OSError:
        return ""


def _one_line(text: str, limit: int = 400) -> str:
    text = re.sub("\ufffd+", " | ", text)
    return " ".join(sanitize.clean_text(text, limit).split())


def _container_lines(root: Path, cid: str) -> list[str]:
    out: list[str] = []
    for log in (root / "containerd" / "root").glob(f"*/{cid}/{cid}-json.log"):
        for raw in _tail(log, CONTAINER_TAIL).splitlines():
            try:
                rec = json.loads(raw)
                text = base64.b64decode(rec.get("msg", ""), validate=False).decode("utf-8", errors="replace")
            except (ValueError, TypeError, AttributeError):
                continue
            if rec.get("stream") == 2 and text.strip():
                out.append("container: " + _one_line(text))
    return out[-2:]


def diagnose(sandbox: str, root: Path | None = None) -> list[str]:
    """ERROR lines about ``sandbox`` from the daemon log, then the failed
    container's stderr; the most specific line comes last."""
    try:
        root = root or state_dir()
        if root is None or not sandbox:
            return []
        errors: list[str] = []
        cids: list[str] = []
        for raw in _tail(root / "daemon.log", DAEMON_TAIL).splitlines():
            if sandbox not in raw or '"ERROR"' not in raw:
                continue
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            if rec.get("level") != "ERROR":
                continue
            text = str(rec.get("msg", ""))
            if rec.get("error"):
                text += ": " + str(rec["error"])
            line = "sbx: " + _one_line(text)
            if line not in errors:
                errors.append(line)
            cids += [c for c in _CONTAINER_ID.findall(text) if c not in cids]
        lines = errors[-2:]
        for cid in cids[-1:]:
            lines += _container_lines(root, cid)
        return lines[-MAX_LINES:]
    except Exception:  # noqa: BLE001 - diagnosis must never fail a run
        return []
