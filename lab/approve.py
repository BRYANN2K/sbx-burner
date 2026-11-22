"""``lab approve --agent NAME``: approve a mixin kit's credential in sbx.

The sandbox proxy only injects a stored credential where the user has
approved it in ``~/.config/sbx/credentials.yaml``. Approving is the user's
choice, so burner never edits that file: this command creates a throwaway
sandbox with the agent's mixin kit attached to the user's terminal, lets
sbx's own "Approve ...?" prompt record the binding, removes the sandbox
and reports what is now approved.
"""

from __future__ import annotations

import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import TextIO

from . import sbx
from .recipe import REPO_ROOT


# The burner-approve-* sandbox runs no agent under the user's global sbx policy
# and is removed right after sbx records the approval.
def approve(
    agent_name: str,
    repo_root: Path = REPO_ROOT,
    out: TextIO | None = None,
    run=subprocess.call,
) -> int:
    out = out or sys.stdout
    agent = sbx.AGENTS.get(agent_name)
    if agent is None:
        print(f"unknown agent {agent_name!r} (see: burner agents)", file=out)
        return 2
    if not agent.mixin_kit:
        print(f"{agent_name} uses sbx's built-in workload: its credential needs no binding", file=out)
        return 2
    kit = repo_root / agent.mixin_kit
    needs = sbx.kit_binding_needs(kit)
    if not needs:
        print(f"{kit} declares no credential capability", file=out)
        return 2
    if not sys.stdin.isatty():
        print(f"{agent_name} approval needs a terminal: sbx asks you interactively. Run: burner approve --agent {agent_name}", file=out)
        return 3
    if not sbx.binding_gaps(needs):
        print(f"{agent_name}: every credential the mixin declares is already approved", file=out)
        return 0

    name = f"burner-approve-{secrets.token_hex(4)}"
    workspace = tempfile.mkdtemp(prefix="burner-approve-")
    try:
        print(f"approving {agent.secret_service} in sbx — answer the prompt below (a throwaway sandbox is used)", file=out)
        code = run(sbx.create(name, "shell", workspace, kits=[str(kit)]))
        if code:
            print(f"sbx create failed ({code}); nothing was approved", file=out)
            return code
    finally:
        run(sbx.rm(name), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.rmtree(workspace, ignore_errors=True)

    left = sbx.binding_gaps(needs)
    if left:
        print("the approval did not cover everything the mixin needs; still missing:", file=out)
        print(sbx.binding_snippet(left), file=out)
        return 3
    for service, mechanisms in needs.items():
        domains = sorted({d for domains in mechanisms.values() for d in domains})
        print(f"approved {service}: {', '.join(domains)}", file=out)
    return 0


def status(repo_root: Path = REPO_ROOT) -> list[dict]:
    """Every mixin kit's credential approval: approved, or the missing domains.

    Reads the kits and sbx's credentials.yaml only; never writes either.
    """
    out = []
    for name, agent in sbx.AGENTS.items():
        if not agent.mixin_kit:
            continue
        row: dict = {"agent": name, "kit": agent.mixin_kit, "approved": False, "missing": {}, "error": ""}
        kit = repo_root / agent.mixin_kit
        if not (kit / f"{kit.name}.yaml").is_file():
            # Same check as build_plan: a missing kit is never "approved".
            row["error"] = f"mixin kit {agent.mixin_kit} is missing"
            out.append(row)
            continue
        try:
            gaps = sbx.binding_gaps(sbx.kit_binding_needs(kit))
        except sbx.BindingUnreadable as exc:
            row["error"] = f"could not read {sbx.credentials_path()}: {exc}"
            out.append(row)
            continue
        except OSError as exc:
            row["error"] = f"could not read {kit}: {exc.strerror or exc}"
            out.append(row)
            continue
        row["approved"] = not gaps
        row["missing"] = {svc: sorted({d for ds in mech.values() for d in ds}) for svc, mech in gaps.items()}
        out.append(row)
    return out
