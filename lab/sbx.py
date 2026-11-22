"""Docker Sandboxes (`sbx`) command builders.

Every function returns an argv list; nothing here runs a process. The runner
executes them, and ``--dry-run`` prints them, so the plan and the real run can
never drift apart.

Flags are taken from the sbx CLI reference (docs.docker.com/reference/cli/sbx,
source: docker/docs data/sbx_cli/*.yaml, checked 2026-11-21 against sbx
v0.48). Anything that could not be confirmed there is marked ``TODO(verify)``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import miniyaml

SBX = "sbx"

# Agent → sbx built-in agent name, sbx secret service, headless argv and the
# hosts the agent itself needs. Credential setup: docs.docker.com/ai/sandboxes/
# agents/claude-code and agents/codex.


@dataclass(frozen=True)
class Agent:
    name: str
    secret_service: str
    setup_commands: tuple[str, ...]
    headless: tuple[str, ...]
    hosts: tuple[str, ...]
    skills_dir: str
    context_file: str
    mixin_kit: str
    interactive_login_note: str = ""
    # ACP (--acp): the agent's ACP server inside the sandbox, how to install
    # it when the agent's kit lacks it, and the install-only hosts for that.
    acp: tuple[str, ...] = ()
    acp_install: str = ""
    acp_install_hosts: tuple[str, ...] = ()
    # Interactive (--interactive): the agent's own TUI, started with the task
    # prompt as its first message; tui_model_flag passes --model to it.
    # TODO(verify): every CLI takes a positional first prompt in TUI mode.
    tui: tuple[str, ...] = ()
    tui_model_flag: str = ""

    @property
    def tui_command(self) -> tuple[str, ...]:
        return self.tui or (self.name,)


# Every repo base kit (base-kali/base-ubuntu/base-remnux) grants the agent
# user `agent ALL=(ALL) NOPASSWD:ALL` via /etc/sudoers.d/agent (0440), which
# lab-ask-independent tool installs rely on.
# TODO(verify): passwordless sudo on the built-in Debian agent path cannot be
# checked from here.
AGENTS: dict[str, Agent] = {
    "claude": Agent(
        name="claude",
        secret_service="anthropic",
        setup_commands=("sbx secret set anthropic",),
        # Documented headless form (ai/sandboxes/workflows/automation):
        #   sbx exec ci-task -- claude --dangerously-skip-permissions -p "..."
        # TODO(verify): `--output-format stream-json --verbose` feeds the live
        # event stream (normalized in lab/agent_stream.py); flag names are from
        # Claude Code docs and not re-confirmed here.
        headless=(
            "claude",
            "--dangerously-skip-permissions",
            "--output-format",
            "stream-json",
            "--verbose",
            "-p",
        ),
        hosts=("api.anthropic.com:443",),
        skills_dir=".claude/skills",
        context_file="CLAUDE.md",
        mixin_kit="kits/agent-claude",
        tui=("claude", "--dangerously-skip-permissions"),
        tui_model_flag="--model",
        interactive_login_note=(
            "Claude Code can also sign in with a subscription through /login inside the sandbox. "
            "That flow is interactive, so unattended runs need a stored key: sbx secret set anthropic"
        ),
        # Verified on sbx 0.54 (2026-11-22): the built-in claude image carries
        # claude at ~/.local/bin but no ACP server and no Node. The ACP
        # adapter is the npm package @agentclientprotocol/claude-agent-acp
        # (successor of zed-industries/claude-code-acp); it drives the
        # sandbox's own claude through CLAUDE_CODE_EXECUTABLE —
        # /home/agent/.local/bin/claude on the built-in agent, a symlink the
        # agent-claude mixin ships at the same path — so the proxy-managed
        # OAuth sentinel in ~/.claude/.credentials.json keeps working.
        acp=("env", "CLAUDE_CODE_EXECUTABLE=/home/agent/.local/bin/claude", "/home/agent/.local/bin/claude-agent-acp"),
        acp_install=(
            "set -euo pipefail; "
            "command -v node >/dev/null || { sudo apt-get update -qq && "
            "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nodejs npm >/dev/null; }; "
            # --ignore-scripts: verified to work without install scripts.
            'npm install -g --ignore-scripts --prefix "$HOME/.local" --no-fund --no-audit '
            "@agentclientprotocol/claude-agent-acp@0.109.1; "
            # Recorded in logs/acp-install.log: what actually got installed.
            'node --version; npm ls -g --prefix "$HOME/.local" --all --json'
        ),
        acp_install_hosts=("deb.debian.org:80", "security.debian.org:80", "registry.npmjs.org:443"),
    ),
    "codex": Agent(
        name="codex",
        secret_service="openai",
        setup_commands=("sbx secret set openai --oauth", "sbx secret set openai"),
        # TODO(verify): the sbx docs show Codex with a prompt only in the
        # interactive form (`sbx run ... -- --dangerously-bypass-approvals-and-sandbox "..."`).
        # `codex exec` is Codex's own non-interactive subcommand; the
        # combination with `sbx exec` is not shown in the sbx docs.
        # TODO(verify): `exec --json` emits the JSONL event stream the runner
        # normalizes (lab/agent_stream.py); the flag is not re-confirmed here.
        headless=("codex", "exec", "--dangerously-bypass-approvals-and-sandbox", "--json"),
        tui=("codex", "--dangerously-bypass-approvals-and-sandbox"),
        tui_model_flag="-m",
        hosts=("api.openai.com:443", "auth.openai.com:443", "chatgpt.com:443"),
        skills_dir=".agents/skills",
        context_file="AGENTS.md",
        mixin_kit="kits/agent-codex",
        # Verified on sbx 0.54 (2026-11-22): the codex kit ships codex 0.171
        # but no ACP server and no Node. The ACP adapter is the npm package
        # @agentclientprotocol/codex-acp (successor of zed-industries/codex-acp,
        # archived); it drives the kit's own codex through CODEX_PATH, so the
        # sbx model gateway and OAuth sentinel keep working.
        acp=("env", "CODEX_PATH=/usr/local/bin/codex", "/home/agent/.local/bin/codex-acp"),
        acp_install=(
            "set -euo pipefail; "
            "command -v node >/dev/null || { sudo apt-get update -qq && "
            "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nodejs npm >/dev/null; }; "
            # --ignore-scripts: verified to work without install scripts.
            'npm install -g --ignore-scripts --prefix "$HOME/.local" --no-fund --no-audit '
            "@agentclientprotocol/codex-acp@2.9.0; "
            # Recorded in logs/acp-install.log: what actually got installed.
            'node --version; npm ls -g --prefix "$HOME/.local" --all --json'
        ),
        acp_install_hosts=("deb.debian.org:80", "security.debian.org:80", "registry.npmjs.org:443"),
    ),
    "cursor": Agent(
        name="cursor",
        secret_service="cursor",
        setup_commands=("sbx secret set cursor --oauth", "sbx secret set cursor"),
        # sbx's own session config is `cursor-agent -p --trust <prompt>`.
        headless=("cursor-agent", "-p", "--trust"),
        hosts=("api2.cursor.sh:443", "api3.cursor.sh:443", "repo42.cursor.sh:443", "cursor.com:443"),
        # The built-in kit declares agent-skills at /home/agent/.cursor/skills.
        skills_dir=".cursor/skills",
        context_file="AGENTS.md",
        mixin_kit="kits/agent-cursor",
        interactive_login_note=("Cursor signs in with `agent login` inside the sandbox; sbx keeps the OAuth record on the host."),
        # Verified on sbx 0.54 (2026-11-22): cursor-agent 2026.11.22 ships a
        # native ACP server — `cursor-agent acp`, no adapter to install.
        # configOptions expose mode (agent/plan/ask) and model
        # (default[] = Auto).
        acp=("/home/agent/.local/bin/cursor-agent", "acp"),
    ),
    "opencode": Agent(
        name="opencode",
        # OpenCode reads provider keys sbx injects as env sentinels. Its own
        # OpenAI OAuth binding works; Anthropic OAuth is not passed through —
        # Anthropic needs an API key.
        secret_service="openai",
        setup_commands=("sbx secret set openai --oauth", "sbx secret set openai", "sbx secret set anthropic"),
        # Verified by Bryan (2026-11-22): `opencode run -m openai/gpt-6-luna`.
        headless=("opencode", "run"),
        hosts=("api.openai.com:443", "auth.openai.com:443", "chatgpt.com:443", "api.anthropic.com:443"),
        skills_dir=".agents/skills",
        context_file="AGENTS.md",
        mixin_kit="kits/agent-opencode",
        interactive_login_note=(
            "OpenCode uses provider keys sbx injects as env (OPENAI_API_KEY and friends); "
            "OpenAI OAuth works, Anthropic OAuth does not reach it."
        ),
        # Verified on sbx 0.54 (2026-11-22): opencode 2.3.2 ships a native
        # ACP server — `opencode acp`, no adapter to install. configOptions
        # expose model (<provider>/<id>, e.g. openai/gpt-6-luna), mode
        # (build/plan) and effort.
        acp=("/usr/local/bin/opencode", "acp"),
    ),
    "devin": Agent(
        name="devin",
        secret_service="devin",
        # Docs (ai/sandboxes/agents/devin): "On first run, Devin prompts you
        # to sign in interactively inside the sandbox", then sbx keeps the
        # credential on the host ("token handled by proxy" in sbx secret ls).
        setup_commands=("sbx run devin <folder>   # sign in once, then exit",),
        # sbx's own startup command is `devin --permission-mode dangerous
        # --respect-workspace-trust=false`; -p is Devin's non-interactive mode.
        headless=("devin", "--permission-mode", "dangerous", "--respect-workspace-trust", "false", "-p"),
        # From the built-in devin kit's network-policy (sbx 0.54, 2026-11-22).
        hosts=("api.devin.ai:443", "server.codeium.com:443", "windsurf.com:443", "unleash.codeium.com:443"),
        # TODO(verify): Devin reads AGENTS.md; its skills directory is not documented.
        skills_dir=".agents/skills",
        context_file="AGENTS.md",
        mixin_kit="kits/agent-devin",
        # Verified on sbx 0.54 (2026-11-22): `devin acp` is a native ACP v1
        # server; configOptions expose mode
        # (accept-edits/smart/ask/plan/bypass) and model (adaptive,
        # swe-2-high, ...). sbx's credential engine writes
        # ~/.local/share/devin/credentials.toml as JSON (docker/sbx-releases
        # #906); burner's Kali kit re-emits it as TOML at start.
        acp=("/home/agent/.local/bin/devin", "acp"),
        interactive_login_note="Devin signs in once inside a sandbox (`sbx run devin <folder>`); sbx then reuses it.",
    ),
}


def secret_check(agent: Agent) -> list[str]:
    """List stored secrets for the agent's service (names only, never values)."""
    return [SBX, "secret", "ls", "--service", agent.secret_service, "--quiet"]


# --- credential bindings -------------------------------------------------
#
# A mixin kit's `credential@1` capability only names the credential; the
# proxy also needs a user-approved binding in ~/.config/sbx/credentials.yaml
# before it will inject the stored secret. `sbx create` records the binding
# after an interactive "Approve ...?" prompt; a non-interactive run never
# sees the prompt, so without the file the sentinel is withheld and the
# agent fails with 401 "Authentication required".


def credentials_path() -> Path:
    """``~/.config/sbx/credentials.yaml`` (``$XDG_CONFIG_HOME`` honoured)."""
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "sbx" / "credentials.yaml"


def kit_binding_needs(kit_dir: Path) -> dict[str, dict[str, set[str]]]:
    """``{service: {mechanism: {domains}}}`` a mixin kit's credential caps need."""
    spec = next(
        (doc for path in sorted(kit_dir.glob("*.yaml")) if isinstance(doc := miniyaml.load(path), dict) and doc.get("capabilities")),
        {},
    )
    needs: dict[str, dict[str, set[str]]] = {}
    for cap in spec.get("capabilities") or []:
        if cap.get("type") != "com.docker.sandbox/credential@1":
            continue
        cfg: dict[str, Any] = cap.get("config") or {}
        mechanisms = needs.setdefault(cfg.get("service", ""), {})
        if api_key := cfg.get("apiKey"):
            mechanisms["apiKey"] = {inj["domain"] for inj in api_key.get("inject") or []}
        if oauth := cfg.get("oauth"):
            domains = set(oauth.get("resourceHosts") or [])
            if host := (oauth.get("tokenEndpoint") or {}).get("host"):
                domains.add(host)
            mechanisms["oauth"] = domains
    return needs


def kits_binding_needs(kits_dir: Path) -> dict[str, dict[str, set[str]]]:
    """The union of ``kit_binding_needs`` over every kit dir in ``kits_dir``."""
    needs: dict[str, dict[str, set[str]]] = {}
    for kit_dir in sorted(kits_dir.glob("*/")):
        for service, mechanisms in kit_binding_needs(kit_dir).items():
            bound = needs.setdefault(service, {})
            for mechanism, domains in mechanisms.items():
                bound.setdefault(mechanism, set()).update(domains)
    return needs


class BindingUnreadable(Exception):
    """credentials.yaml exists but cannot be read as the expected shape."""


def _bindings() -> dict[str, Any]:
    """The ``bindings`` mapping of credentials.yaml ({} when the file is absent).

    TODO(verify): the real file format; sbx writes it with its own YAML
    encoder and miniyaml reads a subset, so anything unexpected is reported
    instead of crashing every mixin run.
    """
    path = credentials_path()
    try:
        doc = miniyaml.load(path)
    except FileNotFoundError:
        return {}
    except (OSError, miniyaml.YAMLError, ValueError, TypeError, AttributeError) as exc:
        raise BindingUnreadable(str(exc)) from exc
    if doc is None:
        return {}
    if not isinstance(doc, dict):
        raise BindingUnreadable("top level is not a mapping")
    bindings = doc.get("bindings") or {}
    if not isinstance(bindings, dict):
        raise BindingUnreadable("'bindings' is not a mapping")
    for service, mechanisms in bindings.items():
        if not isinstance(mechanisms, dict):
            raise BindingUnreadable(f"bindings.{service} is not a mapping")
        for mechanism, spec in mechanisms.items():
            if not isinstance(spec, dict) or not isinstance(spec.get("domains") or [], list):
                raise BindingUnreadable(f"bindings.{service}.{mechanism} has no 'domains' list")
    return bindings


def binding_gaps(needs: dict[str, dict[str, set[str]]]) -> dict[str, dict[str, set[str]]]:
    """The parts of ``needs`` that credentials.yaml does not already bind.

    Raises BindingUnreadable when the file exists but has an unexpected shape.
    """
    bindings = _bindings()
    gaps: dict[str, dict[str, set[str]]] = {}
    for service, mechanisms in needs.items():
        bound = bindings.get(service) or {}
        for mechanism, domains in mechanisms.items():
            missing = domains - {str(d) for d in (bound.get(mechanism) or {}).get("domains") or []}
            if missing:
                gaps.setdefault(service, {})[mechanism] = missing
    return gaps


def binding_snippet(gaps: dict[str, dict[str, set[str]]]) -> str:
    """The credentials.yaml block that approves the missing domains."""
    lines = ["bindings:"]
    for service, mechanisms in gaps.items():
        lines.append(f"  {service}:")
        for mechanism, domains in mechanisms.items():
            lines += [f"    {mechanism}:", "      domains:"] + [f"        - {d}" for d in sorted(domains)]
    return "\n".join(lines)


def create(
    name: str,
    workload: str,
    workspace: str,
    *,
    kits: list[str] | None = None,
    extra_workspaces: list[str] | None = None,
    deny_network: list[str] | None = None,
    template: str | None = None,
    memory: str | None = None,
    cpus: int | None = None,
    publish: list[str] | None = None,
    env: dict[str, str] | None = None,
) -> list[str]:
    """``sbx create AGENT|SANDBOX_KIT [PATH...]``.

    ``workload`` is a built-in agent name or an explicit kit path (``./kit``).
    ``extra_workspaces`` entries use ``PATH[:TARGET][:ro]``.
    """
    argv = [SBX, "create", "--name", name, "--no-progress", "--skills", "off"]
    for kit in kits or []:
        argv += ["--kit", kit]  # experimental flag in the CLI reference
    for host in deny_network or []:
        argv += ["--deny-network", host]
    if template:
        argv += ["--template", template]
    if memory:
        argv += ["--memory", memory]
    if cpus:
        argv += ["--cpus", str(cpus)]
    for port in publish or []:
        argv += ["--publish", port]
    for key, value in (env or {}).items():
        argv += ["--env", f"{key}={value}"]
    argv += [workload, workspace]
    argv += list(extra_workspaces or [])
    return argv


def policy_allow(name: str, hosts: list[str]) -> list[str]:
    """Per-sandbox allow rule; RESOURCES is a comma-separated list."""
    return [SBX, "policy", "allow", "network", "--sandbox", name, ",".join(hosts)]


def policy_deny(name: str, hosts: list[str]) -> list[str]:
    return [SBX, "policy", "deny", "network", "--sandbox", name, ",".join(hosts)]


def policy_rm(name: str, host: str) -> list[str]:
    """Remove one sandbox-scoped rule by resource (one host per call)."""
    return [SBX, "policy", "rm", "network", "--force", "--sandbox", name, "--resource", host]


def policy_log(name: str) -> list[str]:
    """JSON shape (v0.48): ``{updated_at, allowed: [...], blocked: [...]}``."""
    return [SBX, "policy", "log", name, "--json"]


def policy_ls(name: str) -> list[str]:
    return [SBX, "policy", "ls", name, "--json"]


def exec_(
    name: str,
    command: list[str],
    *,
    workdir: str | None = None,
    env: dict[str, str] | None = None,
    interactive: bool = False,
    tty: bool = False,
) -> list[str]:
    """``sbx exec [flags] SANDBOX -- COMMAND``; exit status is the command's.

    ``interactive`` adds ``-i`` (stdin kept open, no TTY) for stdio protocols
    such as ACP; ``tty`` adds ``-it`` for an agent's own TUI on the
    operator's terminal.
    """
    argv = [SBX, "exec"]
    if tty:
        argv.append("-it")
    elif interactive:
        argv.append("-i")
    if workdir:
        argv += ["--workdir", workdir]
    for key, value in (env or {}).items():
        argv += ["--env", f"{key}={value}"]
    return argv + [name, "--", *command]


def egress_probe(name: str, host: str) -> list[str]:
    """In-sandbox probe; exits 0 only when the host is reachable.

    ``-f`` turns the proxy's HTTP 403 for a refused request into a failure.
    """
    target = host if "://" in host else f"https://{host}"
    return exec_(name, ["curl", "-sS", "-f", "-m", "10", "-o", "/dev/null", target])


def template_save(name: str, tag: str) -> list[str]:
    """Snapshot the sandbox filesystem as a local template."""
    return [SBX, "template", "save", name, tag]


def template_rm(tag: str) -> list[str]:
    return [SBX, "template", "rm", tag]


def cp(src: str, dst: str) -> list[str]:
    """One side must be ``SANDBOX:/absolute/path``."""
    return [SBX, "cp", src, dst]


def stop(name: str) -> list[str]:
    return [SBX, "stop", name]


def rm(name: str) -> list[str]:
    return [SBX, "rm", "--force", name]


def attach(name: str) -> list[str]:
    """Attach to the agent interactively (needed for subscription /login)."""
    return [SBX, "run", "--name", name]
