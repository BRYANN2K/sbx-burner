"""Docker Sandboxes (`sbx`) command builders.

Every function returns an argv list; nothing here runs a process. The runner
executes them, and ``--dry-run`` prints them, so the plan and the real run can
never drift apart.

Flags are taken from the sbx CLI reference (docs.docker.com/reference/cli/sbx,
source: docker/docs data/sbx_cli/*.yaml, checked 2026-11-21 against sbx
v0.48). Anything that could not be confirmed there is marked ``TODO(verify)``.
"""

from __future__ import annotations

from dataclasses import dataclass

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
        interactive_login_note=(
            "Claude Code can also sign in with a subscription through /login inside the sandbox. "
            "That flow is interactive, so unattended runs need a stored key: sbx secret set anthropic"
        ),
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
        # TODO(verify): the hosts Devin needs are not documented; sbx grants
        # the built-in agent's endpoints itself. Read `sbx policy log` after
        # the first real run and pin them here.
        hosts=(),
        # TODO(verify): Devin reads AGENTS.md; its skills directory is not documented.
        skills_dir=".agents/skills",
        context_file="AGENTS.md",
        # No mixin kit yet: Devin runs only on recipes that use sbx's built-in
        # workload (no `workload:` in recipe.yaml).
        mixin_kit="",
        interactive_login_note="Devin signs in once inside a sandbox (`sbx run devin <folder>`); sbx then reuses it.",
    ),
}


def secret_check(agent: Agent) -> list[str]:
    """List stored secrets for the agent's service (names only, never values)."""
    return [SBX, "secret", "ls", "--service", agent.secret_service, "--quiet"]


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
) -> list[str]:
    """``sbx exec [flags] SANDBOX -- COMMAND``; exit status is the command's.

    ``interactive`` adds ``-i`` (stdin kept open, no TTY) for stdio protocols
    such as ACP.
    """
    argv = [SBX, "exec"]
    if interactive:
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
