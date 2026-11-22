"""Scope files: who authorized what, against which targets, until when.

A scope file is the single source of truth for a security run. The runner
refuses to start a security recipe without one, and turns it into an sbx
network allow-list so that scope is enforced by the sandbox egress proxy and
not only by the agent prompt.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import jsonschema_lite, miniyaml

SCHEMA_PATH = Path(__file__).parent / "schema" / "scope.schema.json"

# Names that can only resolve to a lab you run yourself (RFC 2606, RFC 6761,
# RFC 6762, RFC 8375 and the ICANN-reserved .internal).
LAB_SUFFIXES = (".localhost", ".test", ".internal", ".lab", ".local", ".example", ".home.arpa")
LAB_NAMES = ("localhost",)

# Techniques that no recipe in this repository may run, whatever the scope says.
NEVER_ALLOWED = ("dos", "ddos", "social-engineering", "phishing", "physical", "data-destruction", "ransomware")

_HOST_RE = re.compile(r"^(?:\*\*?\.)?[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::\d{1,5})?$")


# Marker for values `lab scope new` could not know. A scope that still holds
# one is refused, so an authorization is never invented.
TODO_MARK = "TODO(burner)"


def todo_fields(data: Any, path: str = "") -> list[str]:
    """Paths of the fields that still hold a TODO_MARK value."""
    out: list[str] = []
    if isinstance(data, str):
        if TODO_MARK in data:
            out.append(path or "(root)")
    elif isinstance(data, dict):
        for k, v in data.items():
            out += todo_fields(v, f"{path}.{k}" if path else str(k))
    elif isinstance(data, list):
        for i, v in enumerate(data):
            out += todo_fields(v, f"{path}[{i}]")
    return out


class ScopeError(ValueError):
    """The scope file is missing, invalid, expired or too broad."""


@dataclass
class Scope:
    id: str
    owner: str
    authorization: dict[str, Any]
    not_before: _dt.date
    not_after: _dt.date
    targets: list[dict[str, Any]]
    mode: str = "strict"
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    techniques_allowed: list[str] = field(default_factory=list)
    techniques_forbidden: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def target_hosts(self) -> list[str]:
        hosts: list[str] = []
        for target in self.targets:
            for host in target.get("hosts") or []:
                if host not in hosts:
                    hosts.append(host)
        return hosts

    def in_scope(self, host: str) -> bool:
        """True when ``host`` (optionally ``host:port``) matches a scope target."""
        return not self.denied(host) and any(_matches(p, host) for p in self.target_hosts)

    def denied(self, host: str) -> bool:
        return any(_matches(p, host) for p in self.deny)


def split_host(entry: str) -> tuple[str, str | None]:
    """Split ``host[:port]``; CIDR and bare IPv6 are returned unchanged."""
    if "/" in entry or entry.count(":") > 1:
        return entry, None
    if ":" in entry:
        host, port = entry.rsplit(":", 1)
        return host, port
    return entry, None


def _matches(pattern: str, host: str) -> bool:
    p_host, p_port = split_host(pattern.lower())
    h_host, h_port = split_host(host.lower())
    if p_port and h_port and p_port != h_port:
        return False
    if "/" in p_host:
        try:
            return ipaddress.ip_address(h_host) in ipaddress.ip_network(p_host, strict=False)
        except ValueError:
            return False
    if p_host.startswith("**."):
        return h_host.endswith(p_host[2:])
    if p_host.startswith("*."):
        return h_host.endswith(p_host[1:]) and "." not in h_host[: -len(p_host[1:])]
    return p_host == h_host


def is_lab_host(entry: str) -> bool:
    """True when the entry can only point at a private lab."""
    host, _ = split_host(entry.lower())
    try:
        net = ipaddress.ip_network(host, strict=False)
        return net.is_private or net.is_loopback or net.is_link_local
    except ValueError:
        pass
    host = host.removeprefix("**.").removeprefix("*.")
    return host in LAB_NAMES or ("." + host).endswith(LAB_SUFFIXES)


def _check_host(entry: str, where: str, errors: list[str]) -> None:
    host, port = split_host(entry)
    if entry.strip() in ("*", "**") or host in ("*", "**"):
        errors.append(f"{where}: {entry!r} matches every host; a scope must name its hosts")
        return
    if "://" in entry:
        errors.append(f"{where}: {entry!r} must be a host, not a URL")
        return
    if "/" in host or host.count(":") > 1:
        try:
            net = ipaddress.ip_network(host, strict=False)
        except ValueError:
            errors.append(f"{where}: {entry!r} is not a valid IP or CIDR")
            return
        if net.version == 4 and net.prefixlen < 16:
            errors.append(f"{where}: {entry!r} is wider than /16")
        if net.version == 6 and net.prefixlen < 48:
            errors.append(f"{where}: {entry!r} is wider than /48")
        return
    if not _HOST_RE.match(entry):
        errors.append(f"{where}: {entry!r} is not a valid host pattern")
        return
    if port and not 0 < int(port) < 65536:
        errors.append(f"{where}: {entry!r} has an invalid port")
    bare = host.removeprefix("**.").removeprefix("*.")
    if host != bare and "." not in bare and bare not in ("test", "internal", "lab", "localhost"):
        errors.append(f"{where}: wildcard {entry!r} covers a whole top-level domain")


def load_raw(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        raise ScopeError(f"scope file not found: {p}")
    text = p.read_text(encoding="utf-8")
    try:
        data = json.loads(text) if p.suffix == ".json" else miniyaml.loads(text)
    except (ValueError, miniyaml.YAMLError) as exc:
        raise ScopeError(f"{p}: cannot parse: {exc}") from exc
    if not isinstance(data, dict):
        raise ScopeError(f"{p}: scope must be a mapping")
    return data


def validate(data: dict[str, Any], today: _dt.date | None = None, check_dates: bool = True) -> Scope:
    """Validate a parsed scope document and return a :class:`Scope`.

    Raises :class:`ScopeError` listing every problem found.
    """
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    errors = jsonschema_lite.validate(data, schema)
    if errors:
        raise ScopeError("invalid scope file:\n  - " + "\n  - ".join(errors))

    for where in todo_fields(data):
        errors.append(f"{where}: still a {TODO_MARK} value; edit it before using this scope")

    auth = data["authorization"]
    try:
        not_before = _dt.date.fromisoformat(data["valid"]["not_before"])
        not_after = _dt.date.fromisoformat(data["valid"]["not_after"])
    except ValueError as exc:
        raise ScopeError(f"invalid scope dates: {exc}") from exc

    if not_after < not_before:
        errors.append("valid: not_after is before not_before")
    if (not_after - not_before).days > 366:
        errors.append("valid: a scope may not last longer than one year")
    if check_dates:
        today = today or _dt.date.today()
        if today < not_before:
            errors.append(f"valid: scope is not valid before {not_before}")
        if today > not_after:
            errors.append(f"valid: scope expired on {not_after}")

    if auth["type"] == "written" and not (auth.get("reference") or "").strip():
        errors.append("authorization: type 'written' needs a 'reference' to the written authorization")

    network = data.get("network") or {}
    for i, target in enumerate(data["targets"]):
        if not (target.get("hosts") or target.get("paths")):
            errors.append(f"targets[{i}]: needs 'hosts' or 'paths'")
        for host in target.get("hosts") or []:
            _check_host(host, f"targets[{i}].hosts", errors)
            if auth["type"] == "own-lab" and not is_lab_host(host):
                errors.append(
                    f"targets[{i}].hosts: {host!r} is not a private lab address; "
                    "authorization type 'own-lab' only covers localhost, private IP ranges and "
                    f"{', '.join(LAB_SUFFIXES)}. Use type 'written' with a reference for anything else"
                )
    for key in ("allow", "deny"):
        for host in network.get(key) or []:
            _check_host(host, f"network.{key}", errors)

    techniques = data["techniques"]
    for tech in techniques["allowed"]:
        if tech.lower() in NEVER_ALLOWED:
            errors.append(f"techniques.allowed: {tech!r} is never allowed by this project")

    if errors:
        raise ScopeError("scope refused:\n  - " + "\n  - ".join(errors))

    return Scope(
        id=data["id"],
        owner=data["owner"],
        authorization=auth,
        not_before=not_before,
        not_after=not_after,
        targets=data["targets"],
        mode=network.get("mode", "strict"),
        allow=list(network.get("allow") or []),
        deny=list(network.get("deny") or []),
        techniques_allowed=list(techniques["allowed"]),
        techniques_forbidden=sorted(set(list(techniques.get("forbidden") or []) + list(NEVER_ALLOWED))),
        raw=data,
    )


def load(path: str | Path, today: _dt.date | None = None, check_dates: bool = True) -> Scope:
    return validate(load_raw(path), today=today, check_dates=check_dates)


def network_policy(scope: Scope | None, extra_allow: list[str] | None = None) -> dict[str, list[str]]:
    """Build the sandbox allow/deny lists.

    ``extra_allow`` carries hosts the run itself needs (agent API, pinned tool
    downloads). A host listed in ``deny`` is never allowed, even when a recipe
    or the agent asks for it.
    """
    allow: list[str] = []
    deny: list[str] = list(scope.deny) if scope else []
    candidates = list(extra_allow or [])
    if scope:
        candidates += scope.target_hosts + scope.allow
    for host in candidates:
        if host in allow:
            continue
        if any(_matches(d, host) for d in deny):
            continue
        allow.append(host)
    return {"allow": allow, "deny": deny}
