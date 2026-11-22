"""Ask an agent for its models without a run (``lab models --agent X``).

A throwaway sandbox on the agent's built-in workload, with no recipe and no
target: the global policy, plus the agent's API hosts, plus the ACP
adapter's install hosts for the install window only. The ACP adapter is
installed like a run does, then burner's bridge runs in probe mode
(initialize + session/new, no prompt) and writes the model list. The
sandbox is always removed.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import sbx

EXIT_OK = 0
EXIT_REFUSED = 2
EXIT_PREFLIGHT = 3
EXIT_FAILED = 4

MODELS_FILE = "acp-models.json"  # internal/acp ModelsFile

Run = Callable[..., subprocess.CompletedProcess]


class ProbeError(Exception):
    def __init__(self, message: str, code: int = EXIT_FAILED) -> None:
        super().__init__(message)
        self.code = code


def sandbox_name(agent: str, now: _dt.datetime | None = None) -> str:
    now = now or _dt.datetime.now()
    return f"lab-models-{agent}-{now.strftime('%H%M%S')}"


def steps(agent: sbx.Agent, sandbox: str, workspace: str, bridge: str, transcript: str) -> list[tuple[str, list[str], int]]:
    """The probe's commands, in order: (name, argv, timeout seconds)."""
    out: list[tuple[str, list[str], int]] = [
        ("create", sbx.create(sandbox, agent.name, workspace), 600),
    ]
    install = [h for h in dict.fromkeys(agent.acp_install_hosts) if h not in agent.hosts] if agent.acp_install else []
    if install:
        out.append(("policy-allow-install", sbx.policy_allow(sandbox, install), 60))
    if agent.hosts:
        out.append(("policy-allow", sbx.policy_allow(sandbox, list(agent.hosts)), 60))
    if agent.acp_install:
        out.append(("acp-install", sbx.exec_(sandbox, ["bash", "-c", agent.acp_install], workdir=workspace), 900))
    for host in install:
        out.append((f"policy-close:{host}", sbx.policy_rm(sandbox, host), 60))
    probe = [
        bridge,
        "acp-bridge",
        f"--agent={agent.name}",
        "--probe",
        f"--cwd={workspace}",
        f"--transcript={transcript}",
        "--",
        *sbx.exec_(sandbox, list(agent.acp), workdir=workspace, interactive=True),
    ]
    out.append(("probe", probe, 300))
    return out


def probe(agent_name: str, bridge: str, *, run: Run = subprocess.run, log: Callable[[str], None] = lambda _m: None) -> dict[str, Any]:
    """Return the agent's model list; raises ProbeError."""
    agent = sbx.AGENTS.get(agent_name)
    if agent is None or not agent.acp:
        raise ProbeError(f"{agent_name} is not driven over ACP", EXIT_REFUSED)
    if not bridge or not Path(bridge).is_absolute():
        raise ProbeError("BURNER_ACP_BRIDGE must be burner's absolute path (burner models --refresh sets it)", EXIT_REFUSED)
    if shutil.which(sbx.SBX) is None and run is subprocess.run:
        raise ProbeError("sbx is not installed", EXIT_PREFLIGHT)
    cred = run(sbx.secret_check(agent), capture_output=True, text=True, timeout=30)
    if cred.returncode != 0 or not (cred.stdout or "").strip():
        hint = agent.setup_commands[0] if agent.setup_commands else f"sbx secret set {agent.secret_service}"
        raise ProbeError(f"no {agent.secret_service} credential stored for {agent.name}: {hint}", EXIT_PREFLIGHT)

    # Under burner's home, like run folders: sbx mounts it into the sandbox.
    base = Path(os.environ.get("BURNER_HOME") or Path.home() / ".burner") / "tmp"
    base.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="models-", dir=base))
    os.chmod(tmp, 0o700)
    workspace = tmp / "workspace"
    workspace.mkdir()
    transcript = tmp / "acp-transcript.ndjson"
    sandbox = sandbox_name(agent.name)
    created = False
    try:
        for name, argv, timeout in steps(agent, sandbox, str(workspace), bridge, str(transcript)):
            log(name)
            if name == "create":
                created = True  # a timed-out create may still leave a sandbox
            try:
                res = run(argv, capture_output=True, text=True, timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                raise ProbeError(f"{name} timed out after {timeout} s") from exc
            if res.returncode != 0 and not name.startswith("policy-close"):
                for line in (res.stderr or "").strip().splitlines()[-3:]:
                    log(f"{name}: {line[:200]}")
                raise ProbeError(f"{name} failed (exit {res.returncode})")
        models = tmp / MODELS_FILE
        if not models.is_file():
            raise ProbeError(f"{agent.name} sent no model list")
        data = json.loads(models.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("agent") != agent.name:
            raise ProbeError("unexpected model list")
        return data
    finally:
        if created:
            log("destroy")
            try:
                run(sbx.rm(sandbox), capture_output=True, text=True, timeout=300)
            except (OSError, subprocess.SubprocessError):
                pass
        shutil.rmtree(tmp, ignore_errors=True)
