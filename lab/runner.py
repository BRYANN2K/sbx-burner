"""The lab runner.

create sandbox → enforce scope as network policy → install tools → snapshot →
launch the agent → collect evidence → gate → report → destroy.

``build_plan`` is pure: it returns the exact sbx commands. ``--dry-run``
prints that plan; a real run executes the same objects.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import agent_stream, report, sanitize, sbx, sbx_diag, sources
from . import ask as ask_mod
from . import events as events_mod
from . import evidence as evidence_mod
from . import scope as scope_mod
from .recipe import REPO_ROOT, SCOPE_REQUIRED_CATEGORIES, Recipe

EXIT_OK = 0
EXIT_REFUSED = 2
EXIT_PREFLIGHT = 3
EXIT_RUN_FAILED = 4
EXIT_GATE_FAILED = 5

TARGET_MOUNT = "/home/agent/target"
# Directory a --target-image tarball's parent is mounted at, read-only.
TARGET_IMAGE_MOUNT = "/home/agent/target-image"
# registry/name[:tag][@sha256:…], lowercase path components; same rule as
# burner's imageRef. Refuses option-like ("-x"), spaces and control chars.
IMAGE_REF_RE = re.compile(
    r"^(?:[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]{1,5})?/)?[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$"
)
# Container name --target-port gives the user's app inside the sandbox.
TARGET_CONTAINER = "lab-target"
# Seconds the health check waits for a started container to answer.
TARGET_HEALTH_TIMEOUT = 120
# RepoDigests first (pulled images) then .Id (local builds, tarballs): a
# bare `{{index .RepoDigests 0}}` errors when the list is empty.
INSPECT_FORMAT = "{{if .RepoDigests}}{{index .RepoDigests 0}}{{else}}{{.Id}}{{end}}"
# File under the run dir that holds the resolved digest or image ID.
TARGET_INSPECT_FILE = "target-image.txt"
# Workspace file (under .lab/) that holds the loaded tarball image reference.
TARGET_IMAGE_REF_FILE = "target-image-ref"
# Sourced by every recipe installer; copied next to the recipe tools.
INSTALL_HELPER = "kits/lab-tools/lab-install.sh"
# ACP transcript (R12): the bridge writes raw lines host-side, the runner
# redacts them into ACP_TRANSCRIPT and removes the raw file.
# Host ask that holds the run while the operator uses the agent's own TUI.
INTERACTIVE_ASK = "agent-tui"
ACP_TRANSCRIPT_RAW = "acp-transcript.raw.jsonl"
ACP_TRANSCRIPT = "acp-transcript.jsonl"
ACP_MAX_OPEN_ASKS = 8
# Every teardown step is bounded: SIGINT is ignored while it runs.
TEARDOWN_TIMEOUT = 300
ACP_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/\[\]-]{0,127}$")
# Bridge → runner message types the runner acts on; everything else is dropped.
ACP_EVENT_TYPES = {"agent.message": ("text",), "agent.tool": ("tool", "summary")}
# Optional bridge fields: the tool call's id (updates attach to one action
# line), its command and its status. Capped and sanitised by EventWriter.
ACP_EVENT_OPTIONAL = {"agent.tool": ("detail", "id", "status")}
ACP_TOOL_STATUS = ("pending", "in_progress", "completed", "failed")
_ACP_TOOL_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
# Host steps call sources.py standalone (it has no lab imports, so a plain
# interpreter + absolute path always works, whatever the cwd).
_SOURCES_PY = str(Path(__file__).resolve().with_name("sources.py"))


def _sources_argv(action: str, *args: object) -> list[str]:
    return [sys.executable, _SOURCES_PY, action, *[str(a) for a in args]]


# Hosts probed to prove that egress outside the scope is closed.
DEFAULT_CANARIES = ("example.com",)

_FLAG_HINT = {
    "path": f"--target PATH (mounted read-only at {TARGET_MOUNT})",
    "repo": "--target-repo SRC[@REF]",
    "app": "--target-app PATH|SRC[@REF]",
    "image": "--target-image REF|TAR",
    "port": "--target-image REF|TAR --target-port N",
    "url": "--target-url URL",
}


def agent_prompt(has_scope: bool, skills_dir: str, skills: list[str]) -> str:
    """The agent's first instruction. Names .lab/scope.json only when the run
    writes one, and the skills where this agent's kit mounts them."""
    parts = ["Read AGENTS.md and TASK.md in the current directory, then carry out the task."]
    if has_scope:
        parts.append("Stay inside the scope in .lab/scope.json.")
    else:
        parts.append("Stay on the target named in TASK.md.")
    if skills:
        listed = ", ".join(f"{skills_dir}/{name}/SKILL.md" for name in skills)
        parts.append(f"The skills AGENTS.md mentions are in {listed}.")
    parts.append(
        "Record proof for every finding under evidence/ and write evidence/evidence.json "
        "following .lab/evidence.schema.json. Stop when a stop condition in AGENTS.md is met."
    )
    return " ".join(parts)


class Refused(Exception):
    """The run is refused before anything is created."""

    def __init__(self, message: str, code: int = EXIT_REFUSED) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class Step:
    name: str
    argv: list[str]
    why: str
    # "expect_fail" steps succeed when the command fails (egress probes).
    expect_fail: bool = False
    optional: bool = False
    timeout: int | None = None
    capture_to: str | None = None
    # host=True marks a plain host command (clone, docker save): it runs on
    # the user's machine with the user's credentials, never inside sbx.
    host: bool = False


@dataclass
class Plan:
    recipe: Recipe
    agent: sbx.Agent
    run_id: str
    run_dir: Path
    sandbox: str
    scope: scope_mod.Scope | None
    target: Path | None
    policy: dict[str, list[str]]
    # One of path | repo | app | image | url when a target was chosen this run;
    # target_info carries the resolved values (image ref, ports, url...).
    target_kind: str | None = None
    target_info: dict[str, Any] = field(default_factory=dict)
    # (label, argv, hint) doctor checks run at preflight; states only.
    doctor: list[tuple[str, list[str], str]] = field(default_factory=list)
    # Literal --app-env values redacted from logs, evidence and the report.
    app_env_values: list[str] = field(default_factory=list)
    disk_need: int = 0
    preflight: list[Step] = field(default_factory=list)
    setup: list[Step] = field(default_factory=list)
    agent_step: Step | None = None
    collect: list[Step] = field(default_factory=list)
    teardown: list[Step] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # --prompt/--prompt-file text shown in TASK.md; never part of argv/policy.
    operator_notes: list[dict[str, str]] = field(default_factory=list)
    # --acp: the agent step is burner's ACP bridge (docs/security/acp.md).
    acp: bool = False
    interactive: bool = False
    interactive_timeout: int = 0  # seconds the agent's own TUI may stay open

    @property
    def workspace(self) -> Path:
        return self.run_dir / "workspace"

    def all_steps(self) -> list[Step]:
        agent = [self.agent_step] if self.agent_step else []
        return self.preflight + self.setup + agent + self.collect + self.teardown


def _stamp(now: _dt.datetime) -> str:
    return now.strftime("%Y%m%d-%H%M%S")


def _registry_hosts(ref: str) -> tuple[list[str], str | None]:
    """Egress hosts a `docker pull REF` needs, plus a note when unsure."""
    first = ref.split("/", 1)[0] if "/" in ref else ""
    if "." in first or ":" in first or first == "localhost":
        registry = first
    else:
        registry = "docker.io"
    if registry in ("docker.io", "index.docker.io", "registry-1.docker.io"):
        return ["registry-1.docker.io:443", "auth.docker.io:443", "production.cloudflare.docker.com:443"], None
    if registry == "ghcr.io":
        return ["ghcr.io:443", "pkg-containers.githubusercontent.com:443"], None
    host = registry if ":" in registry else f"{registry}:443"
    return [host], f"TODO(verify): blob CDN host for {registry}"


def _parse_port(value: str) -> tuple[int, int]:
    """``N`` or ``HOST:CONTAINER`` -> (host port, container port), both 1-65535."""
    parts = value.split(":")
    if len(parts) == 1:
        parts = parts * 2
    elif len(parts) != 2:
        raise Refused(f"--target-port must be N or HOST:CONTAINER, got {value!r}")
    host, container = parts
    for port in (host, container):
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise Refused(f"--target-port {value!r}: port {port!r} is not in 1-65535")
    return int(host), int(container)


def _looks_like_tarball(value: str) -> bool:
    """A --target-image argument that names a file, not a registry ref."""
    name = Path(value).name.lower()
    return name.endswith((".tar", ".tar.gz", ".tgz", ".tar.xz", ".tar.zst", ".tar.bz2", ".oci")) or value.startswith(
        ("./", "../", "/", "~")
    )


PATH_DIGEST_MAX_FILES = 20000


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _path_identity(path: Path) -> dict[str, Any]:
    """Identify a host path target before it is mounted.

    A file gives its sha256. A directory gives a sha256 tree digest over the
    sorted ``relative path NUL file sha256 LF`` lines (``.git/`` skipped), its
    file count and, for a git work tree, ``git_head`` and ``dirty`` as extra
    information.
    """
    if path.is_file():
        return {"sha256": _sha256_file(path), "files": 1}

    def readable(p: Path) -> bool:
        if not p.is_file() or ".git" in p.relative_to(path).parts:
            return False
        if p.is_symlink():
            try:
                p.resolve().relative_to(path.resolve())
            except ValueError:
                return False  # a link pointing outside the tree is not read
        return True

    files = sorted(p for p in path.rglob("*") if readable(p))
    identity: dict[str, Any] = {"files": len(files)}
    if len(files) > PATH_DIGEST_MAX_FILES:
        identity["sha256"] = "skipped: too many files"
    else:
        tree = hashlib.sha256()
        for file in files:
            tree.update(f"{file.relative_to(path).as_posix()}\0{_sha256_file(file)}\n".encode())
        identity["sha256"] = tree.hexdigest()
    if (path / ".git").exists():
        head = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
        if head.returncode == 0:
            identity["git_head"] = head.stdout.strip()
            status = subprocess.run(["git", "-C", str(path), "status", "--porcelain"], capture_output=True, text=True, check=False)
            identity["dirty"] = bool(status.stdout.strip())
    return identity


def needs_scope(recipe: Recipe) -> bool:
    return recipe.scope_mode == "required" or recipe.category in SCOPE_REQUIRED_CATEGORIES or recipe.meta.get("risk") in ("medium", "high")


def build_plan(
    recipe: Recipe,
    *,
    agent_name: str = "claude",
    scope_path: str | None = None,
    target: str | None = None,
    target_repo: str | None = None,
    with_submodules: bool = False,
    pr: int | None = None,
    target_app: str | None = None,
    app_install: str | None = None,
    app_cmd: str | None = None,
    app_port: int | None = None,
    app_health: str | None = None,
    app_env: str | None = None,
    target_image: str | None = None,
    target_port: str | None = None,
    target_url: str | None = None,
    runs_dir: Path | None = None,
    now: _dt.datetime | None = None,
    keep: bool = False,
    repo_root: Path = REPO_ROOT,
    operator_notes: list[dict[str, str]] | None = None,
    acp: bool = False,
    interactive: bool = False,
    model: str | None = None,
    permission: str = "auto",
) -> Plan:
    """Validate the request and build the full command plan. Runs nothing."""
    if recipe.errors:
        raise Refused("recipe is invalid:\n  - " + "\n  - ".join(recipe.errors))
    if recipe.is_stub or recipe.linux.get("status") not in ("ready", "beta"):
        raise Refused(f"{recipe.id}: the linux variant is not runnable (status: {recipe.linux.get('status', 'missing')})")
    if agent_name not in sbx.AGENTS:
        raise Refused(f"unknown agent {agent_name!r} (known: {', '.join(sbx.AGENTS)})")
    agent = sbx.AGENTS[agent_name]
    if acp and not agent.acp:
        wired = ", ".join(name for name, a in sbx.AGENTS.items() if a.acp)
        raise Refused(f"--acp is not wired for {agent_name} yet (ACP agents: {wired})")
    if permission not in ("auto", "ask"):
        raise Refused("--permission must be auto or ask")
    if model is not None and not ACP_MODEL_RE.match(model):
        raise Refused(f"invalid --model {model!r}")
    if acp and interactive:
        raise Refused("--acp and --interactive are two ways to drive the agent; pick one")
    if model is not None and not (acp or interactive):
        raise Refused("--model needs --acp or --interactive")
    if model is not None and interactive and not agent.tui_model_flag:
        raise Refused(f"{agent_name}'s own TUI takes no --model from burner")

    scope: scope_mod.Scope | None = None
    if scope_path:
        try:
            scope = scope_mod.load(scope_path)
        except scope_mod.ScopeError as exc:
            raise Refused(str(exc)) from exc
    elif needs_scope(recipe):
        raise Refused(
            f"{recipe.id} is a security recipe and needs a scope file.\n"
            f"Copy {recipe.path.relative_to(repo_root) if recipe.path.is_relative_to(repo_root) else recipe.path}"
            "/scope.example.yaml, edit it, then pass --scope <file>."
        )

    # --- target selection ----------------------------------------------
    given = [
        kind
        for kind, flag in (
            ("path", target),
            ("repo", target_repo),
            ("app", target_app),
            ("image", target_image),
            ("url", target_url),
        )
        if flag
    ]
    declared = recipe.targets
    # --target PATH may come WITH an image, URL or app target as supporting
    # input (for example an OpenAPI schema), when the recipe declares both.
    primary = [k for k in given if k != "path"]
    supporting_path = len(given) == 2 and "path" in given and primary in (["image"], ["url"], ["app"]) and "path" in declared
    if len(given) > 1 and not supporting_path:
        raise Refused(
            "the target flags are exclusive: pick one of --target-repo, --target-app, --target-image/--target-port, "
            "or --target-url (--target PATH may be added to an image, URL or app target when the recipe accepts both)"
        )
    if pr is not None and not target_repo:
        raise Refused("--pr only makes sense with --target-repo")
    if with_submodules and not (target_repo or target_app):
        raise Refused("--with-submodules only makes sense with --target-repo or --target-app")
    app_flags = {
        "--app-install": app_install,
        "--app-cmd": app_cmd,
        "--app-port": app_port,
        "--app-health": app_health,
        "--app-env": app_env,
    }
    if not target_app:
        used = [name for name, value in app_flags.items() if value is not None]
        if used:
            raise Refused(f"{', '.join(used)} only make sense with --target-app")
    if app_health is not None and not app_health.startswith("/"):
        raise Refused(f"--app-health must be an HTTP path starting with '/', got {app_health!r}")
    kind = next((k for k in given if k != "path"), given[0]) if given else None
    if target_port is not None and not target_image:
        raise Refused("--target-port only makes sense with --target-image")
    host_port = container_port = 0
    if target_port is not None:
        host_port, container_port = _parse_port(target_port)
        kind_check = "port"
    else:
        kind_check = kind or "path"
    if kind is not None and kind_check not in declared:
        raise Refused(f"{recipe.id} does not accept target kind {kind_check!r} (declared targets: {', '.join(declared) or 'none'})")
    if kind is None and recipe.target_mode == "required":
        hints = [_FLAG_HINT[k] for k in declared if k in _FLAG_HINT]
        raise Refused(f"{recipe.id} needs a target: pass " + " or ".join(hints or ["a target flag"]))

    target_path: Path | None = None
    image_ref: str | None = None
    tar_path: Path | None = None
    registry_hosts: list[str] = []
    disk_need = 0
    registry_note: str | None = None
    if target:
        target_path = Path(target).expanduser().resolve()
        if not target_path.exists():
            raise Refused(f"target not found: {target_path}")
    if kind == "image":
        assert target_image is not None
        as_path = Path(target_image).expanduser()
        if as_path.exists():
            if not as_path.is_file():
                raise Refused(f"--target-image {target_image}: not a regular file (tarball expected)")
            tar_path = as_path.resolve()
        elif _looks_like_tarball(target_image):
            raise Refused(f"--target-image tarball not found: {target_image}")
        else:
            if not IMAGE_REF_RE.match(target_image):
                raise Refused(f"--target-image {target_image!r}: not an image reference (registry/name[:tag][@sha256:…]) and not a tarball")
            image_ref = target_image
            registry_hosts, registry_note = _registry_hosts(image_ref)
    elif kind == "url":
        assert target_url is not None
        from urllib.parse import urlparse

        parsed = urlparse(target_url)
        try:
            url_port = parsed.port
        except ValueError:
            url_port = "invalid"
        if parsed.scheme not in ("http", "https") or not parsed.hostname or url_port == "invalid":
            raise Refused(f"--target-url {target_url!r}: only http and https URLs are accepted")
        if parsed.username is not None or parsed.password is not None:
            raise Refused("--target-url must not carry credentials (user@ or user:password@); store them with sbx secret")
        url_host = parsed.hostname + (f":{url_port}" if url_port else "")
        if scope is None:
            raise Refused("--target-url needs --scope: the URL host must be authorized by a scope file")
        if not scope.in_scope(url_host):
            raise Refused(f"--target-url {url_host} is not in the scope's targets (scopes are never widened by the runner)")

    repo_url = repo_ref = app_repo_url = None
    if kind == "repo":
        assert target_repo is not None
        try:
            repo_url, parsed_ref = sources.parse_repo(target_repo)
        except sources.SourceError as exc:
            raise Refused(str(exc)) from exc
        repo_ref = parsed_ref

    # --target-app: a local folder or a repo source (cloned like --target-repo).
    app_src_path: Path | None = None
    app_src_is_repo = False
    app_env_values: list[str] = []
    app_env_file: Path | None = None
    detected: dict[str, Any] = {}
    if kind == "app":
        assert target_app is not None
        if app_env is not None:
            app_env_file = Path(app_env).expanduser().resolve()
            if not app_env_file.is_file():
                raise Refused(f"--app-env file not found: {app_env_file}")
            app_env_values = [v for v in sources.parse_env_file(app_env_file).values() if v]
        candidate = Path(target_app).expanduser()
        if candidate.is_dir():
            app_src_path = candidate.resolve()
        elif candidate.exists():
            raise Refused(f"--target-app {target_app}: not a directory (a file is not an app source)")
        else:
            try:
                app_repo_url, _ = sources.parse_repo(target_app)
            except sources.SourceError as exc:
                raise Refused(f"--target-app {target_app}: not a directory and not a repo source ({exc})") from exc
            app_src_is_repo = True
            if pr is not None or target_repo:
                raise Refused("--pr is only accepted with --target-repo")
            if app_port is None:
                raise Refused(
                    "--app-port N is required with a remote --target-app: "
                    "stack detection runs after the host clone and the port is needed for the plan"
                )
        if app_src_path is not None and app_env_file is None:
            # The project's own .env is copied with the app: treat it like
            # --app-env so its values never reach logs, evidence or reports.
            own_env = app_src_path / ".env"
            if own_env.is_file() and not own_env.is_symlink():
                app_env_values = [v for v in sources.parse_env_file(own_env).values() if v]
        if app_src_path is not None:
            env = sources.parse_env_file(app_env_file) if app_env_file else {}
            detected = sources.detect_stack(app_src_path, env) or {}
            if app_port is None:
                app_port = detected.get("port")
            if app_cmd is None:
                app_cmd = detected.get("cmd")
            if app_install is None:
                app_install = detected.get("install")
            if app_health is None:
                app_health = detected.get("health") or "/"
            if not app_cmd:
                raise Refused(f"--target-app {target_app}: could not determine how to start the app (pass --app-cmd CMD and --app-port N)")
            if app_port is None:
                raise Refused(f"--target-app {target_app}: no port detected; pass --app-port N")
        if app_health is None:
            app_health = "/"

    now = now or _dt.datetime.now()
    run_id = f"{_stamp(now)}-{recipe.name}"
    run_dir = (runs_dir or repo_root / "runs") / run_id
    if kind == "app" and app_src_path is not None and sources._contains(app_src_path, run_dir):
        raise Refused(f"--target-app {app_src_path}: {sources.RUNS_INSIDE_APP}")
    sandbox = f"lab-{recipe.name}"[:48].rstrip("-") + f"-{now.strftime('%H%M%S')}"
    # --target-port opens localhost:HOST inside the sandbox: the scope file
    # is never rewritten; the in-memory copy (mirrored to .lab/scope.json)
    # carries an added_by_runner target instead.
    runner_added = [f"localhost:{host_port}"] if host_port else []
    if kind == "app" and app_port:
        runner_added.append(f"localhost:{app_port}")
    if runner_added and scope is not None:
        name = "lab-app" if kind == "app" else TARGET_CONTAINER
        entry = {"name": name, "hosts": runner_added, "added_by_runner": True}
        scope.targets.append(entry)
        scope.raw.setdefault("targets", []).append(dict(entry))
    policy = scope_mod.network_policy(scope, extra_allow=list(agent.hosts) + recipe.network_allow + runner_added)
    # Install-only hosts are opened for the tools step, then closed again.
    # App ecosystems: detected for a local source, the union for a repo
    # source (the stack is only known after the host clone).
    app_hosts = list(sources.ecosystem_hosts(detected.get("ecosystem"))) if app_src_path is not None else []
    if app_src_is_repo:
        app_hosts = sources.all_ecosystem_hosts()
    acp_hosts = list(agent.acp_install_hosts) if acp and agent.acp_install else []
    install_only = [
        h
        for h in dict.fromkeys(recipe.install_allow + app_hosts + acp_hosts)
        if h not in policy["allow"] and not any(scope_mod._matches(d, h) for d in policy["deny"])
    ]

    target_info: dict[str, Any] = {}
    if kind:
        target_info["kind"] = "image" if kind == "image" else kind
    if target_path:
        target_info["path"] = TARGET_MOUNT
        target_info["identity" if kind == "path" else "path_identity"] = _path_identity(target_path)
    if image_ref:
        target_info["image"] = image_ref
        disk_need = 4 << 30  # docker save output is unknown ahead of time; floor only
    if tar_path:
        target_info["image"] = f"tarball:{tar_path.name}"
        disk_need = tar_path.stat().st_size + (1 << 30)
        target_info["source"] = "tarball"
        target_info["identity"] = {"sha256": _sha256_file(tar_path), "files": 1}
    if host_port:
        target_info["host_port"] = host_port
        target_info["container_port"] = container_port
        target_info["url"] = f"http://localhost:{host_port}"
        target_info["added_by_runner"] = runner_added
    if kind == "url":
        target_info["url"] = target_url
    if kind == "repo":
        assert repo_url is not None
        target_info["repo"] = repo_url
        if repo_ref:
            target_info["ref"] = repo_ref
        if pr is not None:
            target_info["pr"] = pr
            target_info["base"] = "origin/HEAD"
        target_info["path"] = TARGET_MOUNT
    if kind == "app":
        assert app_port is not None
        target_info["app"] = app_repo_url or (str(app_src_path) if app_src_path else "")
        target_info["url"] = f"http://localhost:{app_port}"
        target_info["port"] = app_port
        target_info["cmd"] = app_cmd or "(detected by target-app-prepare)"
        target_info["install"] = app_install or ""
        target_info["health"] = app_health or "/"
        if detected.get("ecosystem"):
            target_info["stack"] = detected["ecosystem"]
        if app_src_path is not None:
            target_info["identity"] = _path_identity(app_src_path)
        if app_env_file is not None:
            target_info["env_keys"] = sorted(sources.parse_env_file(app_env_file))

    plan = Plan(
        recipe=recipe,
        agent=agent,
        run_id=run_id,
        run_dir=run_dir,
        sandbox=sandbox,
        scope=scope,
        target=target_path,
        policy=policy,
        target_kind=("image" if kind == "image" else kind),
        target_info=target_info,
        operator_notes=list(operator_notes or []),
        app_env_values=app_env_values,
        disk_need=disk_need,
    )
    workspace = str(plan.workspace)
    linux = recipe.linux

    # --- host steps: resolve sources with the user's credentials ----------
    # Anything that needs the user's git/docker login runs here on the host,
    # before create; the sandbox only receives the result.
    repo_dir = run_dir / "target-repo"
    if kind == "repo":
        clone_argv = _sources_argv("clone", target_repo, repo_dir)
        if repo_ref:
            clone_argv += ["--ref", repo_ref]
        if pr is not None:
            clone_argv += ["--pr", str(pr)]
        if with_submodules:
            clone_argv.append("--submodules")
        plan.setup.append(
            Step(
                "target-clone",
                clone_argv,
                f"clone {repo_url} on the host (your own git credentials; the sandbox gets the tree, never the token)",
                host=True,
                timeout=1800,
            )
        )
        plan.setup.append(
            Step(
                "target-identity",
                _sources_argv("repo-identity", repo_dir, run_dir / "target-identity.json"),
                "record the credential-free repo URL and commit SHA",
                host=True,
            )
        )
    app_src_dir = run_dir / "app-src"
    if app_src_is_repo:
        plan.setup.append(
            Step(
                "target-clone",
                _sources_argv("clone", target_app, app_src_dir) + (["--submodules"] if with_submodules else []),
                f"clone {app_repo_url} on the host for the app source (your own git credentials)",
                host=True,
                timeout=1800,
            )
        )
    if kind == "app":
        prepare_argv = _sources_argv("prepare-app", app_src_dir if app_src_is_repo else app_src_path, workspace)
        for flag, value in (("--install", app_install), ("--cmd", app_cmd), ("--health", app_health), ("--env", app_env_file)):
            if value is not None:
                prepare_argv += [flag, str(value)]
        if app_port is not None:
            prepare_argv += ["--port", str(app_port)]
        plan.setup.append(
            Step(
                "target-app-prepare",
                prepare_argv,
                "copy the app into the workspace (the user's folder is never modified) and detect its stack",
                host=True,
                timeout=600,
            )
        )
        if app_src_is_repo:
            plan.setup.append(
                Step(
                    "target-identity",
                    _sources_argv("repo-identity", app_src_dir, run_dir / "target-identity.json"),
                    "record the credential-free repo URL and commit SHA",
                    host=True,
                )
            )
    tar_dir = run_dir / "target-image"
    if tar_path:
        plan.notes.append(
            "The tarball is staged by hardlink when it is on the same filesystem (same inode as your file, mounted read-only)."
        )
        # Never mount the tarball's parent dir: stage a hardlink/copy into a
        # fresh run-dir subfolder so a tarball in ~/Downloads exposes nothing
        # but itself. The in-sandbox name is always image.tar.
        staged = shlex.quote(str(tar_dir / "image.tar"))
        plan.setup.append(
            Step(
                "target-stage-image",
                [
                    "bash",
                    "-c",
                    f"mkdir -p {shlex.quote(str(tar_dir))} && "
                    f"(ln {shlex.quote(str(tar_path))} {staged} 2>/dev/null || cp -p {shlex.quote(str(tar_path))} {staged})",
                ],
                f"stage {tar_path} into the run dir (the parent dir is never mounted)",
                host=True,
                timeout=600,
            )
        )
    if image_ref:
        plan.setup.append(
            Step(
                "target-resolve-image",
                _sources_argv(
                    "resolve-image",
                    image_ref,
                    tar_dir / "image.tar",
                    "--source-file",
                    tar_dir / "image.json",
                    "--identity",
                    run_dir / "target-identity.json",
                ),
                f"resolve {image_ref} on the host: save a local image, or pull with your docker login, then save "
                "(registry credentials never enter the sandbox)",
                host=True,
                timeout=3600,
            )
        )

    # --- preflight ------------------------------------------------------
    plan.preflight.append(
        Step("credentials", sbx.secret_check(agent), f"check that a host credential is stored for {agent.secret_service}")
    )

    # --- create ---------------------------------------------------------
    kits = [str((repo_root / k).resolve()) for k in recipe.kits]
    if linux.get("workload"):
        if not agent.mixin_kit:
            raise Refused(
                f"{recipe.id} uses its own workload ({linux['workload']}); {agent.name} has no mixin kit yet. "
                f"Use --agent {' or '.join(a.name for a in sbx.AGENTS.values() if a.mixin_kit)} for this recipe."
            )
        workload = str((repo_root / linux["workload"]).resolve())
        kit_dir = (repo_root / agent.mixin_kit).resolve()
        if not (kit_dir / f"{kit_dir.name}.yaml").is_file():
            raise Refused(f"{agent.name}'s mixin kit {agent.mixin_kit} is missing ({kit_dir.name}.yaml not found)")
        kits.insert(0, str(kit_dir))
    else:
        workload = agent.name
    extra = [f"{target_path}:{TARGET_MOUNT}:ro"] if target_path else []
    if kind == "repo":
        # The host clone is mounted read-only like a path target.
        extra.append(f"{repo_dir}:{TARGET_MOUNT}:ro")
    if tar_path or image_ref:
        # TODO(verify): sbx mounts a directory read-only at a custom path
        # (same mechanism as the /home/agent/target mount). For a registry
        # ref this is the run dir the host resolve step saved the tarball in.
        extra.append(f"{tar_dir}:{TARGET_IMAGE_MOUNT}:ro")
    plan.setup.append(
        Step(
            "create",
            sbx.create(
                sandbox,
                workload,
                workspace,
                kits=kits,
                extra_workspaces=extra,
                deny_network=policy["deny"],
                memory=recipe.run.get("memory"),
                publish=list(recipe.run.get("publish") or []),
            ),
            "create the sandbox microVM with the run workspace" + (f" and the target read-only at {TARGET_MOUNT}" if target_path else ""),
        )
    )
    if install_only:
        plan.setup.append(
            Step("policy-allow-install", sbx.policy_allow(sandbox, install_only), "open the install-only hosts for the tools step")
        )
    if policy["allow"]:
        plan.setup.append(
            Step("policy-allow", sbx.policy_allow(sandbox, policy["allow"]), "allow-list for this sandbox: agent API, tools, scope targets")
        )
    strict = scope is not None and scope.mode == "strict"
    if strict:
        probes = list((recipe.run.get("network") or {}).get("probe_denied") or DEFAULT_CANARIES)
        for host in probes:
            if any(scope_mod._matches(p, host) for p in policy["allow"]):
                continue
            plan.setup.append(
                Step(
                    f"egress-probe:{host}",
                    sbx.egress_probe(sandbox, host),
                    "prove that a host outside the scope is unreachable (must fail)",
                    expect_fail=True,
                    timeout=30,
                )
            )
        plan.notes.append(
            "Scope mode is strict: the global sbx policy must be deny-all (sbx policy init deny-all). "
            "The run aborts if an out-of-scope probe succeeds."
        )
    elif scope is not None:
        plan.notes.append(
            "Scope mode is additive: scope hosts are added on top of your global sbx policy; out-of-scope probes are skipped."
        )

    install = recipe.path / str(recipe.run.get("tools") or "tools/install.sh")
    if install.is_file():
        plan.setup.append(
            Step(
                "tools",
                sbx.exec_(sandbox, ["bash", f"{workspace}/.lab/tools/{install.name}"], workdir=workspace),
                "install the recipe's pinned tools inside the sandbox",
                timeout=1800,
            )
        )
    if acp and agent.acp_install:
        plan.setup.append(
            Step(
                "acp-install",
                sbx.exec_(sandbox, ["bash", "-c", agent.acp_install], workdir=workspace),
                f"install {agent.name}'s ACP server inside the sandbox (install window)",
                timeout=900,
            )
        )

    # --- user target (still inside the install window, before the agent) --
    if kind == "app":
        plan.setup.append(
            Step(
                "app-install",
                sbx.exec_(sandbox, ["bash", ".lab/app-install.sh"], workdir=workspace),
                f"install the app's dependencies inside the sandbox ({target_info.get('stack') or 'detected stack'}; "
                "ecosystem hosts are install-only)",
                timeout=1800,
            )
        )
        plan.notes.append(
            "App install runs the ecosystem install inside the sandbox during the install window — "
            "lifecycle scripts (npm postinstall and similar) execute there, never on the host."
        )
    if image_ref:
        # Only the no-host-docker fallback pulls inside the sandbox. The host
        # resolve step marks source "registry-sandbox" in image.json; the two
        # guarded steps open the registry hosts just for that pull.
        # Host steps read the HOST copy; the in-sandbox path does not exist here.
        registry_guard = f"grep -q registry-sandbox {shlex.quote(str(tar_dir / 'image.json'))}"
        plan.setup.append(
            Step(
                "policy-allow-registry",
                ["bash", "-c", f"{registry_guard} && {shlex.join(sbx.policy_allow(sandbox, registry_hosts))} || true"],
                "open the image registry hosts only when the host could not pull (public fallback)",
                host=True,
            )
        )
        if registry_note:
            plan.notes.append(registry_note)
        plan.notes.append("Registry credentials, when needed, come from `sbx secret` / the sandbox proxy: never from flags or files.")
    image_ref_file = f"{workspace}/.lab/{TARGET_IMAGE_REF_FILE}"
    if tar_path or image_ref:
        tar_in_sandbox = shlex.quote(f"{TARGET_IMAGE_MOUNT}/image.tar")
        # Load once. `docker load -q` prints "Loaded image: <name:tag>" or
        # "Loaded image ID: <sha256:...>"; keep the reference for later steps.
        # A registry ref skipped by the host resolve (registry-sandbox) has
        # no tarball: the guard makes the load a no-op.
        plan.setup.append(
            Step(
                "target-load",
                sbx.exec_(
                    sandbox,
                    [
                        "bash",
                        "-c",
                        f"[ -f {tar_in_sandbox} ] || exit 0; set -o pipefail; docker load -q -i {tar_in_sandbox} | tail -n 1 "
                        f"| sed -E 's/^Loaded image( ID)?: //' > {shlex.quote(image_ref_file)}",
                    ],
                    workdir=workspace,
                ),
                "load the user's image tarball inside the sandbox and record its reference",
                timeout=1800,
            )
        )
        image_arg = f'"$(cat {shlex.quote(image_ref_file)})"'
    if image_ref:
        # Fallback only: the host had no daemon, so the sandbox pulls the
        # public ref through the registry hosts opened just above.
        plan.setup.append(
            Step(
                "target-pull",
                sbx.exec_(
                    sandbox,
                    [
                        "bash",
                        "-c",
                        f"grep -q registry-sandbox {shlex.quote(f'{TARGET_IMAGE_MOUNT}/image.json')} || exit 0; "
                        f"docker pull {shlex.quote(image_ref)} && printf %s {shlex.quote(image_ref)} > {shlex.quote(image_ref_file)}",
                    ],
                    workdir=workspace,
                ),
                "public-fallback only: pull the image inside the sandbox when the host has no docker",
                timeout=1800,
            )
        )
        plan.setup.append(
            Step(
                "policy-close-registry",
                [
                    "bash",
                    "-c",
                    f"{registry_guard} || exit 0; " + " && ".join(shlex.join(sbx.policy_rm(sandbox, h)) for h in registry_hosts),
                ],
                "close the registry hosts again after the public-fallback pull",
                host=True,
            )
        )
        image_arg = f'"$(cat {shlex.quote(image_ref_file)})"'

    def _image_cmd(prefix: list[str]) -> list[str]:
        """``docker <prefix> <image>``: always through the recorded reference file."""
        return ["bash", "-c", " ".join(shlex.quote(a) for a in prefix) + f" {image_arg}"]

    if image_ref or tar_path:
        plan.setup.append(
            Step(
                "target-inspect",
                sbx.exec_(sandbox, _image_cmd(["docker", "image", "inspect", "--format", INSPECT_FORMAT]), workdir=workspace),
                "record the resolved image digest (falls back to the image ID)",
                capture_to=TARGET_INSPECT_FILE,
            )
        )
    # The user's container starts only after the install-only hosts are
    # closed, so it lives inside the final allow-list from its first second.
    late_steps: list[Step] = []
    if host_port:
        publish = f"127.0.0.1:{host_port}:{container_port}"
        late_steps.append(
            Step(
                "target-start",
                sbx.exec_(sandbox, _image_cmd(["docker", "run", "-d", "--name", TARGET_CONTAINER, "-p", publish]), workdir=workspace),
                f"start the user's image as container {TARGET_CONTAINER} on 127.0.0.1:{host_port}",
                timeout=300,
            )
        )
        health = f"http://localhost:{host_port}{recipe.target_health}"
        late_steps.append(
            Step(
                "target-health",
                sbx.exec_(
                    sandbox,
                    [
                        "bash",
                        "-c",
                        'for i in $(seq 60); do code="$(curl -s -m 5 -o /dev/null -w "%{http_code}" '
                        + shlex.quote(health)
                        + ' || true)"; case "$code" in 2*|3*|4*) exit 0;; esac; sleep 2; done; '
                        + f'echo "target did not answer on {health} within {TARGET_HEALTH_TIMEOUT}s" >&2; exit 1',
                    ],
                    workdir=workspace,
                ),
                f"wait until the container answers {health} (any 2xx-4xx code) or give up",
                timeout=TARGET_HEALTH_TIMEOUT + 15,
            )
        )
        plan.notes.append(
            f"localhost:{host_port} was added by the runner (the scope file is not rewritten). "
            f"The container {TARGET_CONTAINER} starts after the install-only hosts are closed and shares the sandbox "
            "egress policy: it can reach whatever the allow-list holds, including the agent API host, while it runs. "
            "`sbx rm` removes it at teardown."
        )
    if kind == "app":
        assert app_port is not None
        late_steps.append(
            Step(
                "app-start",
                sbx.exec_(sandbox, ["bash", ".lab/app-start.sh"], workdir=workspace),
                f"start the user's app in the background on localhost:{app_port} (log: .lab/app.log)",
                timeout=300,
            )
        )
        health = f"http://localhost:{app_port}{app_health}"
        late_steps.append(
            Step(
                "app-health",
                sbx.exec_(
                    sandbox,
                    [
                        "bash",
                        "-c",
                        'for i in $(seq 60); do code="$(curl -s -m 5 -o /dev/null -w "%{http_code}" '
                        + shlex.quote(health)
                        + ' || true)"; case "$code" in 2*|3*|4*) exit 0;; esac; sleep 2; done; '
                        + f'echo "the app did not answer on {health} within {TARGET_HEALTH_TIMEOUT}s" >&2; exit 1',
                    ],
                    workdir=workspace,
                ),
                f"wait until the app answers {health} (any 2xx-4xx code) or give up",
                timeout=TARGET_HEALTH_TIMEOUT + 15,
            )
        )
        plan.notes.append(
            f"localhost:{app_port} was added by the runner (the scope file is not rewritten). "
            "The app starts after the install-only hosts are closed and shares the sandbox egress policy. "
            "Its source was copied into the workspace at app/; the user's folder was not modified."
            + (" Real production secrets do not belong in --app-env." if app_env_file else "")
            + (
                " The project's own .env was copied too; its values are redacted from logs and the report."
                if app_env_values and not app_env_file
                else ""
            )
        )

    for host in install_only:
        # TODO(verify): `sbx policy rm network --resource` with a comma-separated list; one call per host is documented.
        plan.setup.append(Step(f"policy-close:{host}", sbx.policy_rm(sandbox, host), "close an install-only host before the agent starts"))
    if install_only:
        plan.notes.append("Install-only hosts are closed before the agent starts: " + ", ".join(install_only))
    plan.setup.extend(late_steps)
    snapshot_tag = f"lab-{recipe.name}:{_stamp(now)}"
    if recipe.run.get("snapshot"):
        plan.setup.append(
            Step(
                "snapshot",
                sbx.template_save(sandbox, snapshot_tag),
                "save a clean snapshot before the agent starts",
                optional=True,
                timeout=1800,
            )
        )

    # --- agent ----------------------------------------------------------
    agent_env: dict[str, str] = {}
    if kind:
        agent_env["LAB_TARGET_KIND"] = "image" if kind == "image" else kind
    if target_path or kind == "repo":
        agent_env["LAB_TARGET_PATH"] = TARGET_MOUNT
    if kind == "repo":
        assert repo_url is not None
        agent_env["LAB_TARGET_REPO"] = repo_url
        if pr is not None:
            agent_env["LAB_TARGET_BASE"] = "origin/HEAD"
            agent_env["LAB_TARGET_HEAD"] = f"pr-{pr}"
    if kind == "app":
        agent_env["LAB_TARGET_URL"] = f"http://localhost:{app_port}"
    if image_ref:
        agent_env["LAB_TARGET_IMAGE"] = image_ref
    if tar_path:
        agent_env["LAB_TARGET_IMAGE"] = f"tarball:{tar_path.name}"
    if host_port:
        agent_env["LAB_TARGET_URL"] = f"http://localhost:{host_port}"
    if kind == "url":
        assert target_url is not None
        agent_env["LAB_TARGET_URL"] = target_url
    # PATH is left as the sandbox sets it (tools and agent CLIs live in several
    # directories); lab-ask is called by its absolute workspace path instead.
    agent_env["LAB_WORKSPACE"] = workspace
    skill_names = [skill.name for skill in recipe.skills()] + [str(n) for n in recipe.run.get("shared_skills") or []]
    prompt = agent_prompt(scope is not None, agent.skills_dir, skill_names)
    if interactive:
        plan.interactive = True
        plan.interactive_timeout = int(recipe.run.get("timeout_minutes", 30)) * 60
        tui = [*agent.tui_command, *([agent.tui_model_flag, model] if model else []), prompt]
        plan.agent_step = Step(
            "agent",
            sbx.exec_(sandbox, tui, workdir=workspace, env=agent_env, tty=True),
            f"open {agent.name}'s own TUI on your terminal with the task as its first prompt; the run goes on when you quit it",
            timeout=None,
        )
    elif acp:
        plan.acp = True
        acp_env = dict(agent_env)
        if model and agent.acp_model_unlisted.startswith("env:"):
            # The adapter merges this into the session config at start, so a
            # model outside the list it offers runs too.
            acp_env[agent.acp_model_unlisted[4:]] = json.dumps({"model": model}, separators=(",", ":"))
        bridge = [
            os.environ.get("BURNER_ACP_BRIDGE") or "burner",
            "acp-bridge",
            f"--agent={agent.name}",
            f"--permission={permission}",
            f"--cwd={workspace}",
            f"--transcript={run_dir / ACP_TRANSCRIPT_RAW}",
            f"--prompt={prompt}",
        ]
        if model:
            bridge.append(f"--model={model}")
        plan.agent_step = Step(
            "agent",
            [*bridge, "--", *sbx.exec_(sandbox, list(agent.acp), workdir=workspace, env=acp_env, interactive=True)],
            f"drive {agent.name} over ACP (burner acp-bridge; permissions: "
            + ("auto-allow, logged" if permission == "auto" else "ask the operator")
            + (f"; model {model}" if model else "")
            + ")",
            timeout=int(recipe.run.get("timeout_minutes", 30)) * 60,
        )
        plan.notes.append(
            "ACP mode: burner declares no client capability and refuses every agent request except "
            "permissions (docs/security/acp.md); the raw transcript is redacted into "
            f"{ACP_TRANSCRIPT}."
        )
    else:
        plan.agent_step = Step(
            "agent",
            sbx.exec_(sandbox, [*agent.headless, prompt], workdir=workspace, env=agent_env),
            f"run {agent.name} headless with the recipe AGENTS.md and skills",
            timeout=int(recipe.run.get("timeout_minutes", 30)) * 60,
        )

    # --- collect + teardown -----------------------------------------------
    plan.collect.append(
        Step(
            "policy-log", sbx.policy_log(sandbox), "save allowed and blocked hosts as evidence", optional=True, capture_to="policy-log.json"
        )
    )
    if not keep:
        plan.teardown.append(Step("destroy", sbx.rm(sandbox), "remove the sandbox and everything in it"))
        # Host-side leftovers: the clone, the app source and the saved tar.
        candidates = (
            repo_dir if kind == "repo" else None,
            app_src_dir if app_src_is_repo else None,
            tar_dir if (image_ref or tar_path) else None,
        )
        leftovers = [d for d in candidates if d]
        if leftovers:
            plan.teardown.append(
                Step(
                    "target-clean",
                    ["rm", "-rf", *[str(d) for d in leftovers]],
                    "remove the host-side clone and saved image tarball",
                    host=True,
                    optional=True,
                )
            )
        if recipe.run.get("snapshot"):
            # TODO(verify): `sbx template rm` may ask for confirmation; no --force is documented.
            plan.teardown.append(Step("snapshot-rm", sbx.template_rm(snapshot_tag), "remove the run snapshot", optional=True))
    else:
        plan.notes.append(f"--keep: the sandbox stays; remove it with: {shlex.join(sbx.rm(sandbox))}")
    if agent.interactive_login_note:
        plan.notes.append(agent.interactive_login_note)

    # --- doctor hooks: preflight states, names only, never tokens ---------
    repo_src = repo_url if kind == "repo" else (app_repo_url if app_src_is_repo else None)
    if repo_src:
        host = repo_src.split("://", 1)[-1].split("/", 1)[0] if "://" in repo_src else repo_src.split("@", 1)[-1].split(":", 1)[0]
        if host == "github.com":
            plan.doctor.append(("gh auth", ["gh", "auth", "status"], "private repos need `gh auth login` on the host"))
        else:
            ls_remote = ["git", *sources.GIT_SAFE_OPTS, "ls-remote", "--heads", "--", repo_src]
            plan.doctor.append(("git ls-remote", ls_remote, "a failure means the repo needs credentials on the host"))
    if image_ref:
        plan.doctor.append(
            (
                "host runtime",
                [sys.executable, str(Path(sources.__file__).resolve()), "host-runtime"],
                "Docker (or colima) or Apple container saves or pulls on the host; a public ref falls back to a sandbox pull",
            )
        )
        plan.doctor.append(
            (
                "image presence",
                ["docker", "image", "inspect", "--", image_ref],
                "missing images are pulled with your registry login (docker or container)",
            )
        )
        auths = sorted(sources._docker_config_auths())
        if auths:
            plan.notes.append("docker logins on this host: " + ", ".join(auths))
    return plan


def render_plan(plan: Plan) -> str:
    recipe = plan.recipe
    out = [
        f"Plan for {recipe.id} (dry run: nothing is executed)",
        f"  agent:     {plan.agent.name}",
        f"  sandbox:   {plan.sandbox}",
        f"  image:     {recipe.linux.get('image')}",
        f"  run dir:   {plan.run_dir}",
        f"  scope:     {plan.scope.id if plan.scope else 'none'}",
        f"  target:    {_target_summary(plan)}",
        *_app_lines(plan),
        f"  allow:     {', '.join(plan.policy['allow']) or 'nothing'}",
        f"  deny:      {', '.join(plan.policy['deny']) or 'nothing extra'}",
        "",
        "Workspace files:",
    ]
    out += [f"  {rel}" for rel in workspace_manifest(plan)]
    out += ["", "Steps:"]
    for i, step in enumerate(plan.all_steps(), 1):
        flag = " (must fail)" if step.expect_fail else " (best effort)" if step.optional else ""
        flag += " [host]" if step.host else ""
        out += [f"  {i}. {step.name}{flag}: {step.why}", f"     $ {shlex.join(step.argv)}"]
    out += [f"  {len(plan.all_steps()) + 1}. report: gate the evidence, write report.md and report.json"]
    if plan.notes:
        out += ["", "Notes:"] + [f"  - {n}" for n in plan.notes]
    return "\n".join(out)


def _app_lines(plan: Plan) -> list[str]:
    """How the app will be installed and started, so it is checked before Run."""
    if plan.target_kind != "app":
        return []
    info = plan.target_info
    parts = [info.get("stack") or "app"]
    if info.get("install"):
        parts.append(f"install: {info['install']}")
    parts += [f"start: {info.get('cmd')}", f"port {info.get('port')}", f"health {info.get('health') or '/'}"]
    return ["  app run:   " + " · ".join(str(p) for p in parts)]


def _target_summary(plan: Plan) -> str:
    """The chosen target kind and its resolved value for the dry run."""
    info = plan.target_info
    if not plan.target_kind:
        return "none"
    if plan.target_kind == "path":
        return f"path {plan.target}"
    if plan.target_kind == "image":
        value = str(info.get("image"))
        if info.get("host_port"):
            value += f" on http://localhost:{info['host_port']} (container {TARGET_CONTAINER})"
        return f"image {value}"
    if plan.target_kind == "repo":
        ref = f" (pr #{info['pr']})" if info.get("pr") else f"@{info['ref']}" if info.get("ref") else ""
        return f"repo {info.get('repo')}{ref} mounted at {TARGET_MOUNT}"
    if plan.target_kind == "app":
        return f"app {info.get('app')} on {info.get('url')}"
    return f"url {info.get('url')}"


def workspace_manifest(plan: Plan) -> list[str]:
    """Relative paths the runner writes into the workspace."""
    recipe = plan.recipe
    files = ["AGENTS.md", "TASK.md", ".lab/evidence.schema.json", "evidence/"]
    if plan.agent.context_file != "AGENTS.md":
        files.insert(1, plan.agent.context_file)
    if plan.scope:
        files.append(".lab/scope.json")
    if plan.target_kind == "app":
        files += ["app/", ".lab/app.json", ".lab/app-install.sh", ".lab/app-start.sh"]
    for skill in recipe.skills():
        files.append(f"{plan.agent.skills_dir}/{skill.name}/")
    for name in recipe.run.get("shared_skills") or []:
        files.append(f"{plan.agent.skills_dir}/{name}/")
    if (recipe.path / "tools").is_dir():
        files.append(".lab/tools/")
    if (recipe.path / "fixtures").is_dir():
        files.append("fixtures/")
    files.append(".lab/bin/lab-ask")
    return files


def _target_section(plan: Plan) -> list[str]:
    """TASK.md `## Target`: how to reach it and which env vars describe it."""
    info, kind = plan.target_info, plan.target_kind
    if not kind:
        return []
    env = [f"LAB_TARGET_KIND={kind}"]
    lines = ["", "## Target", ""]
    if kind == "path":
        lines.append(f"- The user's files are mounted read-only at `{TARGET_MOUNT}`.")
        env.append(f"LAB_TARGET_PATH={TARGET_MOUNT}")
    elif kind == "repo":
        ref = f" (pr #{info['pr']}, base {info['base']})" if info.get("pr") else f"@{info['ref']}" if info.get("ref") else ""
        lines += [
            f"- The repo `{info.get('repo')}{ref}` was cloned on the host and is mounted read-only at `{TARGET_MOUNT}`.",
            "- Its history (`.git/`) is intact; the clone carries no credentials.",
        ]
        env += [f"LAB_TARGET_PATH={TARGET_MOUNT}", f"LAB_TARGET_REPO={info.get('repo')}"]
        if info.get("pr"):
            env += [f"LAB_TARGET_BASE={info['base']}", f"LAB_TARGET_HEAD=pr-{info['pr']}"]
    elif kind == "app":
        lines += [
            f"- The user's app runs inside the sandbox at `{info.get('url')}` (started after the install window closed).",
            "- Its source was copied to `app/` in the workspace; install/start used `.lab/app-install.sh` and "
            "`.lab/app-start.sh` (lifecycle scripts ran inside the sandbox, log: `.lab/app.log`).",
        ]
        if info.get("stack"):
            lines.append(f"- Detected stack: `{info['stack']}` (start: `{info.get('cmd')}`).")
        if info.get("env_keys"):
            lines.append(f"- `--app-env` applied to `app/.env` (keys: {', '.join(info['env_keys'])}; values are never logged).")
        env.append(f"LAB_TARGET_URL={info.get('url')}")
    elif kind == "image":
        image = str(info.get("image"))
        if image.startswith("tarball:"):
            lines.append(f"- The user's image was loaded from a tarball into the sandbox Docker engine ({image[8:]}).")
        else:
            lines.append(f"- Image `{image}` is pulled and loaded in the sandbox Docker engine.")
        env.append(f"LAB_TARGET_IMAGE={image}")
        if info.get("host_port"):
            host_port, container_port = info["host_port"], info["container_port"]
            lines += [
                f"- The user's app runs at `http://localhost:{host_port}` (container `{TARGET_CONTAINER}`, "
                f"host port {host_port} to container port {container_port}).",
                f"- `localhost:{host_port}` was added by the runner; it is not from your scope file.",
                "- The container shares the sandbox egress policy: it can reach whatever the allow-list "
                "holds, including the agent API host, while it runs.",
            ]
            env.append(f"LAB_TARGET_URL=http://localhost:{host_port}")
    elif kind == "url":
        lines.append(f"- Remote app `{info.get('url')}` (in scope).")
        env.append(f"LAB_TARGET_URL={info.get('url')}")
    if kind != "path" and plan.target:
        lines.append(f"- Supporting files from the user (for example a schema) are mounted read-only at `{TARGET_MOUNT}`.")
        env.append(f"LAB_TARGET_PATH={TARGET_MOUNT}")
    lines.append(f"- Environment: `{', '.join(env)}`")
    return lines


def task_markdown(plan: Plan) -> str:
    recipe = plan.recipe
    lines = [
        f"# Task: {recipe.id}",
        "",
        str(recipe.meta.get("summary", "")),
        "",
        "## This run",
        "",
        f"- Run ID: `{plan.run_id}`",
        f"- Workspace (read-write): `{plan.workspace}`",
        f"- Evidence directory: `{plan.workspace}/evidence`",
        "- Evidence file: `evidence/evidence.json` (schema: `.lab/evidence.schema.json`)",
        f"- Recipe field in the evidence file: `{recipe.id}`",
    ]
    if plan.target:
        lines.append(f"- Target (read-only): `{TARGET_MOUNT}`")
    lines += _target_section(plan)
    if plan.scope:
        scope = plan.scope
        lines += [
            "",
            "## Scope",
            "",
            f"- Scope ID: `{scope.id}` (full file: `.lab/scope.json`)",
            f"- Valid: {scope.not_before} to {scope.not_after}",
            f"- In-scope hosts: {', '.join(scope.target_hosts) or 'none (local paths only)'}",
            f"- Allowed techniques: {', '.join(scope.techniques_allowed)}",
            f"- Forbidden techniques: {', '.join(scope.techniques_forbidden)}",
            *(
                [f"- Risky techniques the operator acknowledged in the scope: {', '.join(scope.techniques_risky)}"]
                if scope.techniques_risky
                else []
            ),
            "",
            "The sandbox network policy only allows the hosts above plus the agent API and tool hosts. "
            "A blocked connection is the policy working: do not try to route around it. Record it as out of scope.",
        ]
    if plan.operator_notes:
        lines += ["", "## Operator notes", ""]
        for note in plan.operator_notes:
            text, _ = evidence_mod.redact(str(note.get("text", "")))
            lines.append(f"- [{note.get('source', 'prompt')}] {text}")
    lines += [
        "",
        "## Asking the operator",
        "",
        f'- `{plan.workspace}/.lab/bin/lab-ask "QUESTION" [--choice X]... [--text] [--timeout S]` '
        "(also `$LAB_WORKSPACE/.lab/bin/lab-ask`) asks the operator and prints the answer.",
        "- An answer is valid only when lab-ask returns it (exit 0). Exit 3 means no answer: use your documented fallback.",
        "- Never guess on destructive or out-of-scope actions: ask, or record the question as a hypothesis.",
        "",
        "## Evidence rules",
        "",
        "- A finding needs a PoC and at least one artifact file under `evidence/`.",
        "- Anything you could not prove goes to `hypotheses`, never to `findings`.",
        "- Never copy secrets in clear text: keep the first 4 characters and mask the rest.",
        "- Artifact paths are relative to `evidence/`.",
        "",
    ]
    return "\n".join(lines)


def prepare_workspace(plan: Plan, repo_root: Path = REPO_ROOT) -> None:
    recipe, ws = plan.recipe, plan.workspace
    (ws / "evidence").mkdir(parents=True, exist_ok=True)
    (ws / ".lab").mkdir(exist_ok=True)
    shutil.copy2(recipe.path / "AGENTS.md", ws / "AGENTS.md")
    (ws / "TASK.md").write_text(task_markdown(plan), encoding="utf-8")
    if plan.agent.context_file != "AGENTS.md":
        (ws / plan.agent.context_file).write_text("@AGENTS.md\n@TASK.md\n", encoding="utf-8")
    shutil.copy2(evidence_mod.SCHEMA_PATH, ws / ".lab" / "evidence.schema.json")
    if plan.scope:
        (ws / ".lab" / "scope.json").write_text(json.dumps(plan.scope.raw, indent=2) + "\n", encoding="utf-8")
    skills_root = ws / plan.agent.skills_dir
    for skill in recipe.skills():
        shutil.copytree(skill, skills_root / skill.name, dirs_exist_ok=True)
    for name in recipe.run.get("shared_skills") or []:
        shutil.copytree(repo_root / "skills" / name, skills_root / name, dirs_exist_ok=True)
    if (recipe.path / "tools").is_dir():
        shutil.copytree(recipe.path / "tools", ws / ".lab" / "tools", dirs_exist_ok=True)
        helper = repo_root / INSTALL_HELPER
        if helper.is_file():
            shutil.copy2(helper, ws / ".lab" / "tools" / helper.name)
    # Optional lab material (compose files, sample targets) shipped by the recipe.
    fixtures = recipe.path / "fixtures"
    if fixtures.is_dir():
        shutil.copytree(fixtures, ws / "fixtures", dirs_exist_ok=True)
    # lab-ask: the agent's channel to the operator (answered only by the host).
    ask_src = Path(__file__).parent / "kit" / "lab-ask"
    if ask_src.is_file():
        bin_dir = ws / ".lab" / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ask_src, bin_dir / "lab-ask")
        (bin_dir / "lab-ask").chmod(0o755)


Exec = Callable[[list[str], int | None], "subprocess.CompletedProcess[str]"]
# Runs the ACP bridge: (argv, timeout, on_line(line, reply), abort_check).
# ``reply(obj)`` writes one JSON line to the bridge's stdin.
AcpExec = Callable[
    [list[str], "int | None", "Callable[[str, Callable[[dict[str, Any]], None]], None]", "Callable[[], bool]"],
    "subprocess.CompletedProcess[str]",
]
# Streams the agent step: (argv, timeout, on_line, abort_check) -> result.
StreamExec = Callable[
    [list[str], "int | None", "Callable[[str], None]", "Callable[[], bool]"],
    "subprocess.CompletedProcess[str]",
]


def _default_exec(argv: list[str], timeout: int | None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)


def _default_acp_exec(
    argv: list[str],
    timeout: int | None,
    on_line: Callable[[str, Callable[[dict[str, Any]], None]], None],
    abort_check: Callable[[], bool],
) -> subprocess.CompletedProcess[str]:
    """Run burner's ACP bridge with a stdin pipe for operator answers."""
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    wlock = threading.Lock()
    out: list[str] = []
    err: list[str] = []

    def reply(obj: dict[str, Any]) -> None:
        with wlock:
            try:
                assert proc.stdin is not None
                proc.stdin.write(json.dumps(obj) + "\n")
                proc.stdin.flush()
            except (OSError, ValueError):
                pass

    def pump() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            out.append(line)
            try:
                on_line(line, reply)
            except Exception:  # noqa: S110 - the reader must outlive a bad callback
                pass

    def pump_err() -> None:
        assert proc.stderr is not None
        for line in proc.stderr:
            if sum(len(x) for x in err) < 1 << 20:
                err.append(line)

    threads = [threading.Thread(target=pump, daemon=True), threading.Thread(target=pump_err, daemon=True)]
    for t in threads:
        t.start()
    deadline = (time.monotonic() + timeout) if timeout else None
    timed_out = False
    while proc.poll() is None:
        if abort_check():
            proc.terminate()
            break
        if deadline and time.monotonic() > deadline:
            timed_out = True
            proc.terminate()
            break
        time.sleep(0.05)
    try:
        rc = proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        rc = proc.wait()
    for t in threads:
        t.join(timeout=3)
    if timed_out:
        rc = 124
    return subprocess.CompletedProcess(argv, rc, "".join(out), "".join(err))


def _acp_line_handler(
    agent: str,
    emit: Callable[..., Any],
    ask_bridge: Any,
    log: Callable[[str], None],
    skipped: list[int],
    seeds: evidence_mod.Seeds | None = None,
) -> Callable[[str, Callable[[dict[str, Any]], None]], None]:
    """Validate bridge lines; only known shapes reach events or the operator."""
    ask_slots = threading.BoundedSemaphore(ACP_MAX_OPEN_ASKS)

    def handle(line: str, reply: Callable[[dict[str, Any]], None]) -> None:
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            skipped[0] += 1
            return
        if not isinstance(msg, dict):
            skipped[0] += 1
            return
        kind = msg.get("t")
        if kind == "event":
            fields_allowed = ACP_EVENT_TYPES.get(str(msg.get("type")))
            data = msg.get("fields")
            if fields_allowed is None or not isinstance(data, dict):
                skipped[0] += 1
                return
            fields = {k: str(data[k]) for k in fields_allowed if isinstance(data.get(k), str)}
            if len(fields) != len(fields_allowed):
                skipped[0] += 1
                return
            for k in ACP_EVENT_OPTIONAL.get(str(msg.get("type")), ()):
                v = data.get(k)
                if not isinstance(v, str) or not v:
                    continue
                if k == "id" and not _ACP_TOOL_ID_RE.match(v):
                    continue
                if k == "status" and v not in ACP_TOOL_STATUS:
                    continue
                fields[k] = v[:2000]
            emit(str(msg["type"]), agent=agent, **fields)
        elif kind == "ask":
            ask_id = str(msg.get("id", ""))
            choices = msg.get("choices") if isinstance(msg.get("choices"), list) else []
            choices = [str(c) for c in choices[:64]]
            question = str(msg.get("question", ""))
            allow_text = bool(msg.get("allow_text"))
            if not ask_id.startswith("acp-") or not question:
                skipped[0] += 1
                return

            if not ask_slots.acquire(blocking=False):
                # More open questions than the bridge itself allows: no answer.
                reply({"t": "answer", "id": ask_id, "value": None})
                return

            def wait() -> None:
                try:
                    value = ask_bridge.ask_host(ask_id, question, choices, allow_text)
                    reply({"t": "answer", "id": ask_id, "value": value})
                finally:
                    ask_slots.release()

            threading.Thread(target=wait, daemon=True).start()
        elif kind == "log":
            shown, _ = evidence_mod.redact(str(msg.get("text", "")), seeds=seeds, agent=True)
            log("    acp: " + sanitize.clean_text(shown)[:500])
        else:
            skipped[0] += 1

    return handle


ACP_TRANSCRIPT_MAX = 64 << 20


def _redact_acp_transcript(run_dir: Path, secrets: list[str], seeds: evidence_mod.Seeds | None = None) -> None:
    """R12: keep a redacted transcript, drop the raw one (always)."""
    raw = run_dir / ACP_TRANSCRIPT_RAW
    try:
        if raw.is_symlink() or not raw.is_file():
            return
        with raw.open("rb") as fh:
            data = fh.read(ACP_TRANSCRIPT_MAX + 1)
        text = data[:ACP_TRANSCRIPT_MAX].decode("utf-8", errors="replace")
        if len(data) > ACP_TRANSCRIPT_MAX:
            text += "\n[transcript truncated at 64 MiB]\n"
        safe, _ = evidence_mod.redact(text, secrets, seeds, agent=True)
        (run_dir / ACP_TRANSCRIPT).write_text(safe, encoding="utf-8")
    finally:
        raw.unlink(missing_ok=True)


def _check_bridge(plan: Plan, path: str) -> None:
    """BURNER_ACP_BRIDGE must be an executable file outside the run."""
    if not path:
        raise Refused("--acp runs through burner (burner run --acp); BURNER_ACP_BRIDGE is not set")
    bridge = Path(path)
    if not bridge.is_absolute():
        raise Refused("BURNER_ACP_BRIDGE must be an absolute path")
    real = bridge.resolve()
    if not real.is_file() or not os.access(real, os.X_OK):
        raise Refused(f"BURNER_ACP_BRIDGE is not an executable file: {path}")
    for root in (plan.run_dir, plan.target):
        if root is not None and real.is_relative_to(Path(root).resolve()):
            raise Refused("BURNER_ACP_BRIDGE must not live in the run directory or the target")


def _ignore_sigint() -> Any:
    """Ignore SIGINT (main thread only); returns the handler to restore."""
    if threading.current_thread() is not threading.main_thread():
        return None
    try:
        return signal.signal(signal.SIGINT, signal.SIG_IGN)
    except ValueError:
        return None


def _seed_from_target(plan: Plan, seeds: evidence_mod.Seeds) -> None:
    """Harvest secret values from the host copy of the target and its git
    history, so a partial value echoed by the agent is masked on screen."""
    roots = [plan.target] if plan.target else []
    for name in ("target-repo", "app-src"):
        candidate = plan.run_dir / name
        if candidate.is_dir() and not candidate.is_symlink():
            roots.append(candidate)
    for root in roots:
        try:
            seeds.scan_tree(root)
            if root.is_dir():
                seeds.scan_git(root, sources.GIT_SAFE_OPTS)
        except OSError:
            continue


def _default_stream_exec(
    argv: list[str],
    timeout: int | None,
    on_line: Callable[[str], None],
    abort_check: Callable[[], bool],
) -> subprocess.CompletedProcess[str]:
    """Run argv while streaming stdout lines to on_line as they arrive.

    The whole agent step uses this so agent.message/agent.tool events and
    lab-ask questions appear live; ``abort_check`` lets the ask bridge kill
    the agent for ``--on-ask fail``.
    """
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out: list[str] = []

    def pump() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            out.append(line)
            try:
                on_line(line)
            except Exception:  # noqa: S110 - the stream reader must outlive a bad callback
                pass

    reader = threading.Thread(target=pump, daemon=True)
    reader.start()
    deadline = (time.monotonic() + timeout) if timeout else None
    timed_out = False
    while proc.poll() is None:
        if abort_check():
            proc.terminate()
            break
        if deadline and time.monotonic() > deadline:
            timed_out = True
            proc.terminate()
            break
        time.sleep(0.05)
    try:
        rc = proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        rc = proc.wait()
    reader.join(timeout=10)
    err = proc.stderr.read() if proc.stderr else ""
    if timed_out:
        rc = 124
    return subprocess.CompletedProcess(argv, rc, "".join(out), err or "")


def _replay_stream_exec(execute: Exec) -> StreamExec:
    """Adapt a buffered Exec to the streaming contract: run, then replay
    stdout lines through on_line. Used when the caller replaced ``execute``
    (tests) but gave no ``stream_exec``; real runs use _default_stream_exec."""

    def run(argv: list[str], timeout: int | None, on_line: Callable[[str], None], _abort: Callable[[], bool]):
        proc = execute(argv, timeout)
        for line in (proc.stdout or "").splitlines(keepends=True):
            on_line(line)
        return proc

    return run


def preflight(plan: Plan, execute: Exec = _default_exec, which: Callable[[str], str | None] = shutil.which) -> None:
    """Check sbx and the agent credential before anything is created.

    The runner never reads, asks for or stores a key: it only checks that the
    host keychain already holds one, and prints the setup command otherwise.
    """
    if which(sbx.SBX) is None:
        raise Refused(
            "sbx is not installed or not on PATH. Install Docker Sandboxes: https://docs.docker.com/ai/sandboxes/install/",
            EXIT_PREFLIGHT,
        )
    if plan.disk_need:
        base = plan.run_dir
        while not base.exists() and base != base.parent:
            base = base.parent
        free = shutil.disk_usage(base).free
        if free < plan.disk_need:
            raise Refused(
                f"not enough free disk for the image target: need ~{plan.disk_need >> 30} GiB, have {free >> 30} GiB under {base}",
                EXIT_PREFLIGHT,
            )
    agent = plan.agent
    proc = execute(plan.preflight[0].argv, 60)
    if proc.returncode != 0 or not proc.stdout.strip():
        setup = "\n".join(f"    {cmd}" for cmd in agent.setup_commands)
        message = (
            f"No stored credential for {agent.name} (sbx secret service: {agent.secret_service}).\n"
            f"One-time setup on the host (the key stays in your OS keychain; the sandbox only sees a placeholder):\n{setup}"
        )
        if agent.interactive_login_note:
            message += f"\n{agent.interactive_login_note}"
        raise Refused(message, EXIT_PREFLIGHT)
    binding_preflight(plan)


def binding_preflight(plan: Plan) -> None:
    """Refuse when the mixin kit's credential binding is not approved yet.

    Runs on the dry-run path as well, so the interactive menu can offer the
    approval before the user starts a run.
    """
    agent = plan.agent
    if not (agent.mixin_kit and plan.recipe.linux.get("workload")):
        return
    needs: dict[str, dict[str, set[str]]] = {}
    for step in plan.setup:
        for i, arg in enumerate(step.argv[:-1]):
            if arg != "--kit":
                continue
            for service, mechanisms in sbx.kit_binding_needs(Path(step.argv[i + 1])).items():
                bound = needs.setdefault(service, {})
                for mechanism, domains in mechanisms.items():
                    bound.setdefault(mechanism, set()).update(domains)
    try:
        gaps = sbx.binding_gaps(needs)
    except sbx.BindingUnreadable as exc:
        raise Refused(
            f"could not read {sbx.credentials_path()} ({exc}); run burner approve --agent {agent.name} or check the file",
            EXIT_PREFLIGHT,
        ) from exc
    if gaps:
        raise Refused(
            f"the {agent.name} mixin needs an approved credential binding: without one the sandbox "
            f"proxy withholds the stored {agent.secret_service} credential and the agent fails with "
            'HTTP 401 "Authentication required".\n'
            f"Missing approvals (recorded in {sbx.credentials_path()}):\n{sbx.binding_snippet(gaps)}\n"
            f"run: burner approve --agent {agent.name}",
            EXIT_PREFLIGHT,
        )


_DURATION_RE = re.compile(r"^timeout=(\d+)([smh])?$")


def parse_on_ask(value: str | None, yes: bool) -> dict[str, Any]:
    """``--on-ask timeout=<dur>|skip|fail`` (+ ``--yes`` default: skip)."""
    if value is None:
        return {"mode": "skip"} if yes else {"mode": "timeout", "seconds": 1800}
    if value == "skip":
        return {"mode": "skip"}
    if value == "fail":
        return {"mode": "fail"}
    match = _DURATION_RE.match(value)
    if not match:
        raise Refused(f"--on-ask: expected timeout=<dur>|skip|fail, got {value!r}")
    seconds = int(match.group(1)) * {"s": 1, "m": 60, "h": 3600}[match.group(2) or "s"]
    if seconds <= 0:
        raise Refused("--on-ask timeout must be at least one second")
    return {"mode": "timeout", "seconds": seconds}


def _ignore_closed_pipe(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap an output function so OSError (BrokenPipeError…) is dropped."""

    def call(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except OSError:
            return None

    return call


def _events_writer(plan: Plan, events: str | None) -> events_mod.EventWriter:
    """Open the --events target; it must live in the run dir, never the workspace."""
    if not events:
        return events_mod.NullWriter(plan.run_id)
    if events == "-":
        return events_mod.EventWriter("-", plan.run_id)
    path = Path(events)
    if not path.is_absolute():
        path = plan.run_dir / path
    resolved = path.resolve()
    if resolved.is_relative_to(plan.workspace.resolve()):
        raise Refused(f"--events {events}: the events file cannot live inside the workspace")
    if not resolved.is_relative_to(plan.run_dir.resolve()):
        raise Refused(f"--events {events}: the events file must stay inside the run dir")
    return events_mod.EventWriter(resolved, plan.run_id)


_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def doctor(plan: Plan, execute: Exec = _default_exec, log: Callable[[str], None] = print) -> None:
    """Non-fatal source checks: prints states and names only, never tokens."""
    for label, argv, hint in plan.doctor:
        try:
            ok = execute(argv, 60).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            ok = False
        log(f"doctor {label}: {'ok' if ok else 'not available'} ({hint})")


def execute_plan(
    plan: Plan,
    execute: Exec = _default_exec,
    log: Callable[[str], None] | None = None,
    *,
    events: str | None = None,
    on_ask: str | None = None,
    answers: str | Path | None = None,
    yes: bool = False,
    stream_exec: StreamExec | None = None,
    acp_exec: AcpExec | None = None,
) -> int:
    """Run the plan. Always tears the sandbox down and always writes a report.

    With ``--events`` every step, agent message/tool call, finding, blocked
    host, ask/answer and the final done go to the NDJSON event writer; human
    output stays on the ``log`` channel (stderr when ``--events -``).
    """
    if plan.interactive and parse_on_ask(on_ask, yes)["mode"] != "timeout":
        raise Refused("--interactive needs an operator: not with --yes or --on-ask skip|fail")
    if log is None:
        log = (lambda s: print(s, file=sys.stderr)) if events == "-" else print
    if plan.acp:
        # Before anything is created: the bridge is burner's own binary.
        _check_bridge(plan, os.environ.get("BURNER_ACP_BRIDGE", ""))
    run_dir = plan.run_dir
    # 0700: control.sock is live before its chmod 0600 lands; no gap for others.
    run_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(run_dir, 0o700)
    prepare_workspace(plan)
    writer = _events_writer(plan, events)
    # Secrets seen in this run (target, history, tool output): masked in
    # events, logs, the transcript and the report, fragments included.
    seeds = evidence_mod.Seeds()
    for value in plan.app_env_values:
        seeds.add(value)
    writer.seeds = seeds
    # The reader of the event stream or the log (burner) may be gone, e.g.
    # after a forced quit. A broken pipe must never stop the teardown.
    emit = _ignore_closed_pipe(writer.emit)
    log = _ignore_closed_pipe(log)
    ask_bridge = ask_mod.AskBridge(plan.workspace, run_dir, on_ask=parse_on_ask(on_ask, yes), answers=answers, emit=emit, log=log)
    started = _dt.datetime.now().astimezone().isoformat(timespec="seconds")
    transcript: list[dict[str, Any]] = []
    status, code, created = "completed", EXIT_OK, False

    def run_step(step: Step, exec_fn: Exec | None = None) -> bool:
        emit("step", name=step.name, status="start")
        log(f"==> {step.name}: {step.why}")
        try:
            proc = (exec_fn or execute)(step.argv, step.timeout)
            rc, out, err = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            rc, out, err = 124, "", f"timed out after {step.timeout}s"
        transcript.append({"step": step.name, "argv": step.argv, "exit_code": rc})
        if rc != 0 and not step.expect_fail and step.argv and Path(step.argv[0]).name == "sbx":
            # sbx often says only "failed to run sandbox container": add
            # the daemon's own ERROR lines for this sandbox (best effort).
            diag = sbx_diag.diagnose(plan.sandbox)
            if diag:
                err = (err or "") + "\n--- sbx daemon ---\n" + "\n".join(diag) + "\n"
        agent_text = step.name == "agent"
        safe_out, _ = evidence_mod.redact(out or "", plan.app_env_values, seeds, agent_text)
        safe_err, _ = evidence_mod.redact(err or "", plan.app_env_values, seeds, agent_text)
        (run_dir / "logs").mkdir(exist_ok=True)
        (run_dir / "logs" / f"{step.name.replace(':', '_')}.log").write_text(
            f"$ {shlex.join(step.argv)}\n[exit {rc}]\n--- stdout ---\n{safe_out}\n--- stderr ---\n{safe_err}\n", encoding="utf-8"
        )
        if step.capture_to and rc == 0:
            (run_dir / step.capture_to).write_text(safe_out, encoding="utf-8")
        ok = (rc != 0) if step.expect_fail else (rc == 0)
        emit("step", name=step.name, status="ok" if ok else ("skip" if step.optional else "fail"), detail=f"exit {rc}")
        if not ok and not step.optional:
            log(f"    failed (exit {rc}); see {run_dir / 'logs'}")
        return ok or step.optional

    # finding candidates: evidence.json may change while the agent works.
    seen_findings: dict[str, str] = {}
    watch_stop = threading.Event()
    evidence_file = plan.workspace / "evidence" / "evidence.json"

    def _watch_findings() -> None:
        last_mtime = 0
        ticks = 0
        while not watch_stop.is_set():
            ticks += 1
            if ticks % 5 == 0:
                seeds.scan_artifacts(plan.workspace / "evidence")
            try:
                mtime = evidence_file.stat().st_mtime_ns
            except OSError:
                mtime = 0
            if mtime and mtime != last_mtime:
                last_mtime = mtime
                try:
                    data = json.loads(evidence_file.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    data = None
                if isinstance(data, dict):
                    for finding in data.get("findings") or []:
                        if not isinstance(finding, dict):
                            continue
                        fid = str(finding.get("id") or "")
                        if not fid or fid in seen_findings:
                            continue
                        seen_findings[fid] = str(finding.get("title") or "")
                        fields: dict[str, Any] = {"id": fid, "title": seen_findings[fid], "status": "candidate"}
                        if finding.get("severity") in _SEVERITIES:
                            fields["severity"] = finding["severity"]
                        emit("finding", **fields)
            watch_stop.wait(0.4)

    watcher = threading.Thread(target=_watch_findings, daemon=True)

    try:
        for step in plan.setup:
            if step.name == "create":
                created = True
            if not run_step(step):
                if step.expect_fail:
                    status = "aborted: egress outside the scope is open"
                    log(
                        "    An out-of-scope host is reachable from the sandbox. Set the global policy to deny-all\n"
                        "    (sbx policy reset, then sbx policy init deny-all) or use network.mode: additive in the scope."
                    )
                    code = EXIT_REFUSED
                else:
                    status, code = f"failed at step {step.name}", EXIT_RUN_FAILED
                break
        else:
            assert plan.agent_step is not None
            normalize = agent_stream.for_agent(plan.agent.name)
            streamer = stream_exec or (_default_stream_exec if execute is _default_exec else _replay_stream_exec(execute))
            skipped = [0]

            def _agent_exec(
                argv: list[str],
                timeout: int | None,
                _normalize: Callable[[str], Any] = normalize,
                _skipped: list[int] = skipped,
                _streamer: StreamExec = streamer,
            ) -> subprocess.CompletedProcess[str]:
                def on_line(line: str) -> None:
                    normalized, n = _normalize(line)
                    _skipped[0] += n
                    for event_type, fields in normalized:
                        emit(event_type, **fields)

                return _streamer(argv, timeout, on_line, lambda: ask_bridge.abort)

            if plan.interactive:

                def _agent_exec(  # noqa: F811 - the operator drives the agent's own TUI
                    argv: list[str], timeout: int | None
                ) -> subprocess.CompletedProcess[str]:
                    # burner (or the flag CLI) runs argv on the operator's
                    # terminal, then answers "done"; the runner waits here.
                    emit("handoff", name="agent", argv=list(argv))
                    answer = ask_bridge.ask_host(
                        INTERACTIVE_ASK,
                        "the agent's own TUI is open on your terminal",
                        ["done"],
                        False,
                        exempt_timeout_s=plan.interactive_timeout,
                    )
                    if answer == "done":
                        return subprocess.CompletedProcess(argv, 0, "interactive session ended\n", "")
                    return subprocess.CompletedProcess(argv, 1, "", "no operator closed the interactive session\n")

            elif plan.acp:
                acp_runner = acp_exec or _default_acp_exec
                handler = _acp_line_handler(plan.agent.name, emit, ask_bridge, log, skipped, seeds)
                unattended = ask_bridge.on_ask["mode"] != "timeout"

                def _agent_exec(  # noqa: F811 - ACP replaces the headless streamer
                    argv: list[str],
                    timeout: int | None,
                    _runner: AcpExec = acp_runner,
                    _handler: Any = handler,
                    _unattended: bool = unattended,
                ) -> subprocess.CompletedProcess[str]:
                    if _unattended:
                        argv = [argv[0], argv[1], "--unattended", *argv[2:]]
                    return _runner(argv, timeout, _handler, lambda: ask_bridge.abort)

            _seed_from_target(plan, seeds)
            try:
                ask_bridge.start()
            except ask_mod.AskError as exc:
                raise Refused(str(exc)) from exc
            try:
                watcher.start()
                if not run_step(plan.agent_step, _agent_exec):
                    status, code = "agent failed or timed out", EXIT_RUN_FAILED
                if ask_bridge.abort:
                    status, code = "aborted: the operator channel was closed (--on-ask fail)", EXIT_RUN_FAILED
            finally:
                watch_stop.set()
                watcher.join(timeout=3)
                ask_bridge.stop()
            if skipped[0]:
                log(f"    agent stream: {skipped[0]} upstream line(s) skipped")
        for step in plan.collect:
            if created:
                run_step(step)
        ask_bridge._scan_forged()
        # TODO(verify): `sbx policy log` JSON is assumed {blocked: [{host: ...}]}.
        policy_log = run_dir / "policy-log.json"
        if policy_log.is_file():
            try:
                plog = json.loads(policy_log.read_text(encoding="utf-8"))
                for entry in plog.get("blocked") or []:
                    host = entry.get("host") if isinstance(entry, dict) else entry
                    if host:
                        emit("blocked", host=str(host))
            except (OSError, json.JSONDecodeError):
                pass
    finally:
        # A second Ctrl+C (or burner forwarding the first) must not cut the
        # teardown short: the sandbox would stay up.
        previous = _ignore_sigint()
        try:
            try:
                for step in plan.teardown:
                    # Host teardown (clone/tar cleanup) runs even when the sandbox
                    # was never created; sandbox teardown needs `created`.
                    if created or step.host:
                        bounded = step if step.timeout else dataclasses.replace(step, timeout=TEARDOWN_TIMEOUT)
                        if not run_step(bounded) and step.name == "destroy":
                            log(f"    the sandbox may remain: sbx ls, then sbx rm --force {plan.sandbox}")
            finally:
                # After destroy (redaction must never keep the sandbox up);
                # the raw transcript is removed either way.
                if plan.acp:
                    _redact_acp_transcript(run_dir, plan.app_env_values, seeds)
        finally:
            if previous is not None:
                signal.signal(signal.SIGINT, previous)

    resolved = run_dir / TARGET_INSPECT_FILE
    if resolved.is_file():
        plan.target_info["resolved"] = resolved.read_text(encoding="utf-8").strip()
    operator_notes = []
    for note in plan.operator_notes:
        raw = str(note.get("text", ""))
        shown, _ = evidence_mod.redact(sanitize.clean_text(raw))
        operator_notes.append({"source": note.get("source", "prompt"), "text": shown, "sha256": hashlib.sha256(raw.encode()).hexdigest()})
    identity_file = run_dir / "target-identity.json"
    if identity_file.is_file():
        try:
            identity = json.loads(identity_file.read_text(encoding="utf-8"))
            if identity.get("source"):
                plan.target_info["source"] = identity["source"]
            plan.target_info.setdefault("identity", {}).update(identity)
        except json.JSONDecodeError:
            plan.notes.append("target-identity.json was not valid JSON")
    run_meta = {
        "id": plan.run_id,
        "recipe": plan.recipe.id,
        "agent": plan.agent.name,
        "sandbox": plan.sandbox,
        "scope_id": plan.scope.id if plan.scope else None,
        "scope": {"id": plan.scope.id, "risky_acknowledged": plan.scope.techniques_risky} if plan.scope else None,
        "target": plan.target_info or (str(plan.target) if plan.target else None),
        "policy": plan.policy,
        "started": started,
        "finished": _dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "status": status,
        "steps": transcript,
        "operator_notes": operator_notes,
        "asks": ask_bridge.report_asks(),
    }
    if ask_bridge.forged:
        run_meta["forged_answers"] = len(ask_bridge.forged)
    emit("step", name="report", status="start")
    evidence_dir = plan.workspace / "evidence"
    try:
        data = evidence_mod.load(evidence_dir)
    except (FileNotFoundError, ValueError) as exc:
        data = evidence_mod.empty(plan.recipe.id, f"No usable evidence file was produced ({exc}). Run status: {status}.")
        if code == EXIT_OK:
            code = EXIT_GATE_FAILED
    result = evidence_mod.gate(data, evidence_dir, scope=plan.scope, extra_values=plan.app_env_values, seeds=seeds)
    if not result.ok:
        fallback = evidence_mod.empty(plan.recipe.id, "The evidence file does not follow the schema; no finding was accepted.")
        errors = result.schema_errors
        result = evidence_mod.gate(fallback, evidence_dir)
        result.schema_errors = errors
        if code == EXIT_OK:
            code = EXIT_GATE_FAILED
    for finding in (result.evidence or {}).get("findings") or []:
        if not isinstance(finding, dict):
            continue
        fields = {"id": str(finding.get("id") or ""), "title": str(finding.get("title") or ""), "status": "proven"}
        if finding.get("severity") in _SEVERITIES:
            fields["severity"] = finding["severity"]
        cvss = finding.get("cvss")
        if isinstance(cvss, dict) and cvss.get("vector"):
            fields["cvss"] = str(cvss["vector"])
        emit("finding", **fields)
    for demoted in result.demoted:
        fid = str(demoted.get("id") or "?")
        emit("finding", id=fid, title=seen_findings.get(fid) or fid, status="rejected")
    if ask_bridge.forged:
        n = len(ask_bridge.forged)
        result.warnings.append(f"{n} forged answer file(s) in the workspace were ignored; the host ask log is authoritative")
        if isinstance(result.evidence, dict):
            current = str(result.evidence.get("summary") or "")
            result.evidence["summary"] = (current + f" {n} forged answer file(s) were detected and ignored.").strip()
    summary = report.write(run_dir, run_meta, result)
    emit("step", name="report", status="ok")
    emit("done", exit_code=code, status=status, report=str(run_dir / "report.md"))
    writer.close()
    log(
        f"==> report: {summary['counts']['findings']} finding(s), {summary['counts']['hypotheses']} hypothesis(es), "
        f"{len(result.demoted)} demoted, {result.redactions} redaction(s)"
    )
    log(f"    {run_dir / 'report.md'}")
    return code
