"""``lab scope new``: write a scope file for one recipe from the chosen target.

The recipe's own ``scope.example.yaml`` is the template: its techniques,
network mode, notes and extra fields stay. Only what the target tells us is
filled in (hosts, authorization type, dates). Anything the generator cannot
know is written as a ``TODO(burner): ...`` value, and ``scope.validate``
refuses a file that still holds one, so an authorization is never invented.
"""

from __future__ import annotations

import datetime as _dt
import getpass
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import miniyaml
from . import scope as scope_mod
from .recipe import Recipe

TODO = scope_mod.TODO_MARK
_EXAMPLE_DOMAINS = ("example.com", "example.org", "example.net")


class ScopeNewError(ValueError):
    """The target cannot produce a scope for this recipe."""


def burner_home() -> Path:
    env = os.environ.get("BURNER_HOME")
    return Path(env) if env else Path.home() / ".burner"


def scopes_dir() -> Path:
    return burner_home() / "scopes"


def _url_host(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ScopeNewError(f"--target-url {url!r}: use an http(s) URL with a host")
    if "*" in parts.hostname:
        raise ScopeNewError(f"--target-url {url!r}: a URL names one host; list wildcards in the scope file yourself")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return f"{parts.hostname.lower()}:{port}"


def _host_port(value: str | int | None) -> str | None:
    """``N`` or ``HOST:CONTAINER`` from --target-port / --app-port: the host side."""
    if value in (None, ""):
        return None
    text = str(value)
    port = text.split(":", 1)[0]
    if not port.isdigit() or not 0 < int(port) < 65536:
        raise ScopeNewError(f"port {text!r} is not a valid port")
    return f"localhost:{port}"


def target_hosts(
    *,
    target_url: str | None = None,
    target_port: str | int | None = None,
    app_port: str | int | None = None,
) -> list[str]:
    """Hosts the chosen target gives; empty when it gives none (path, repo)."""
    if target_url:
        return [_url_host(target_url)]
    for port in (target_port, app_port):
        host = _host_port(port)
        if host:
            return [host]
    return []


def _owner() -> str:
    try:
        out = subprocess.run(["git", "config", "--get", "user.name"], capture_output=True, text=True, timeout=5)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        return getpass.getuser()
    except (OSError, KeyError):
        return f"{TODO}: your name"


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _todo_replace(value: Any) -> Any:
    """Template placeholders ("REPLACE ...") become TODO values."""
    if isinstance(value, str) and "REPLACE" in value:
        cleaned = re.sub(r"REPLACE:?\s*(with)?\s*", "", value).strip()
        return f"{TODO}: {cleaned}" if cleaned else f"{TODO}: fill in"
    if isinstance(value, list):
        return [_todo_replace(v) for v in value]
    if isinstance(value, dict):
        return {k: _todo_replace(v) for k, v in value.items()}
    return value


def _example_host(entry: str) -> bool:
    host, _ = scope_mod.split_host(entry.lower())
    host = host.removeprefix("**.").removeprefix("*.")
    return any(host == d or host.endswith("." + d) for d in _EXAMPLE_DOMAINS)


def generate(
    recipe: Recipe,
    *,
    target_url: str | None = None,
    target_port: str | int | None = None,
    app_port: str | int | None = None,
    owner: str | None = None,
    auth: str | None = None,
    reference: str | None = None,
    days: int = 30,
    today: _dt.date | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Return the scope document and notes on what was kept from the example."""
    example = recipe.path / "scope.example.yaml"
    if not example.is_file():
        raise ScopeNewError(f"{recipe.id} has no scope.example.yaml to start from")
    if not 1 <= days <= 366:
        raise ScopeNewError("--days must be between 1 and 366")
    data = _todo_replace(miniyaml.loads(example.read_text(encoding="utf-8")))
    notes: list[str] = []
    hosts = target_hosts(target_url=target_url, target_port=target_port, app_port=app_port)
    targets = data.get("targets") or []

    if hosts:
        first = next((t for t in targets if t.get("hosts")), None)
        if first is None:
            first = {"name": "target"}
            targets.insert(0, first)
        first["name"] = _slug(hosts[0].split(":")[0]) or "target"
        first["hosts"] = hosts
        # The example's notes describe its bundled lab; keep them only when
        # they are a TODO for the user (a program's rules, for example).
        if first.get("notes") and TODO not in str(first["notes"]):
            del first["notes"]
            notes.append("dropped the example target's notes (they describe the recipe's bundled lab)")
        # Other host targets describe the example lab, not this target.
        targets = [t for t in targets if t is first or not t.get("hosts")]
        data["targets"] = targets
        network = data.setdefault("network", {})
        for key in ("allow", "deny"):
            kept = [h for h in network.get(key) or [] if not _example_host(h) or _example_host(hosts[0])]
            if len(kept) != len(network.get(key) or []):
                notes.append(f"dropped the example's network.{key} hosts; add your own if the target needs them")
            network[key] = kept
    else:
        kept = [h for t in targets for h in t.get("hosts") or []]
        if kept:
            notes.append("kept the recipe's example hosts (" + ", ".join(kept) + "); check them against your target")

    all_hosts = [h for t in data.get("targets") or [] for h in t.get("hosts") or []]
    remote = [h for h in all_hosts if not scope_mod.is_lab_host(h)]
    kind = auth or ("written" if remote else "own-lab")
    if kind not in ("own-lab", "written"):
        raise ScopeNewError("--auth must be own-lab or written")
    if kind == "own-lab" and remote:
        raise ScopeNewError(f"{', '.join(remote)} is not a lab address: use --auth written --reference REF")
    authorization: dict[str, Any] = {"type": kind}
    if kind == "written":
        ref = (reference or "").strip()
        authorization["reference"] = ref or f"{TODO}: link or id of the written authorization"
    data["authorization"] = authorization

    start = today or _dt.date.today()
    data["valid"] = {"not_before": start.isoformat(), "not_after": (start + _dt.timedelta(days=days)).isoformat()}
    data["owner"] = owner or _owner()
    host_part = _slug(all_hosts[0]) if all_hosts else "local"
    data["id"] = f"{_slug(recipe.name)}-{host_part}"[:63].strip("-")
    data["schema_version"] = "1"
    return data, notes


def todos(data: Any) -> list[str]:
    """Paths of the fields that still hold a TODO value."""
    return scope_mod.todo_fields(data)


_PLAIN = re.compile(r"^[A-Za-z_][A-Za-z0-9_./@-]*$")
_KEYWORDS = {"true", "false", "null", "yes", "no", "on", "off", "~"}


def _scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    if value is None:
        return "null"
    text = str(value)
    if _PLAIN.match(text) and text.lower() not in _KEYWORDS:
        return text
    return json.dumps(text, ensure_ascii=False)


def dump(data: Any, indent: int = 0) -> str:
    """Small YAML writer for scope documents (read back by lab.miniyaml)."""
    pad = " " * indent
    lines: list[str] = []
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, dict) and v:
                lines.append(f"{pad}{k}:")
                lines.append(dump(v, indent + 2))
            elif isinstance(v, list) and v and any(isinstance(x, dict | list) for x in v):
                lines.append(f"{pad}{k}:")
                lines.append(dump(v, indent + 2))
            elif isinstance(v, list):
                lines.append(f"{pad}{k}: [" + ", ".join(_scalar(x) for x in v) + "]")
            elif isinstance(v, dict):
                lines.append(f"{pad}{k}: {{}}")
            else:
                lines.append(f"{pad}{k}: {_scalar(v)}")
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                body = dump(item, indent + 2).split("\n")
                lines.append(f"{pad}- {body[0].lstrip()}")
                lines += body[1:]
            else:
                lines.append(f"{pad}- {_scalar(item)}")
    return "\n".join(lines)


def render(recipe: Recipe, data: dict[str, Any]) -> str:
    head = [
        f"# Scope for {recipe.id}, written by `lab scope new` from the recipe's scope.example.yaml.",
        f"# Edit every {TODO} value: `lab scope <this file>` refuses the file until none is left.",
        "",
    ]
    order = ["schema_version", "id", "owner", "authorization", "valid", "targets", "network", "techniques"]
    ordered = {k: data[k] for k in order if k in data}
    ordered.update({k: v for k, v in data.items() if k not in ordered})
    return "\n".join(head) + dump(ordered) + "\n"


def default_path(recipe: Recipe, data: dict[str, Any]) -> Path:
    """~/.burner/scopes/<recipe>-<host>.yaml, numbered instead of overwritten."""
    hosts = [h for t in data.get("targets") or [] for h in t.get("hosts") or []]
    base = f"{_slug(recipe.name)}-{_slug(hosts[0]) if hosts else 'local'}"
    path = scopes_dir() / f"{base}.yaml"
    n = 2
    while path.exists():
        path = scopes_dir() / f"{base}-{n}.yaml"
        n += 1
    return path


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


def blocking(errors: list[str]) -> list[str]:
    """Errors that editing TODO values will not fix."""
    return [e for e in errors if f"still a {TODO} value" not in e]


def check(data: dict[str, Any]) -> list[str]:
    """Validation errors (empty when the scope is ready to use)."""
    try:
        scope_mod.validate(data)
    except scope_mod.ScopeError as exc:
        return [line.strip().removeprefix("- ") for line in str(exc).splitlines()[1:] if line.strip()]
    return []


def summary(data: dict[str, Any]) -> dict[str, Any]:
    valid = data.get("valid") or {}
    days = 0
    try:
        days = (_dt.date.fromisoformat(valid["not_after"]) - _dt.date.fromisoformat(valid["not_before"])).days
    except (KeyError, TypeError, ValueError):
        pass
    return {
        "hosts": [h for t in data.get("targets") or [] for h in t.get("hosts") or []],
        "auth": (data.get("authorization") or {}).get("type", ""),
        "days": days,
    }
