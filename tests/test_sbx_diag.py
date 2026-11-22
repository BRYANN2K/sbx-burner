"""sbx daemon diagnosis for steps that fail with no useful stderr."""

from __future__ import annotations

import base64
import json

from lab import runner, sbx_diag
from tests.test_runner import NOW, FakeSbx

CID = "d2328760d5146add50331e8e0c05c68f514f18be03e8668b8b80e196d3816058"
NAME = "lab-unit-103000"


def _state(tmp_path, name=NAME):
    root = tmp_path / "sandboxd"
    (root / "containerd" / "root" / "svc" / CID).mkdir(parents=True)
    lines = [
        json.dumps({"level": "INFO", "msg": "created virtual network", "network": name}),
        "not json " + name + ' "ERROR"',
        json.dumps(
            {
                "level": "ERROR",
                "msg": "create sandbox failed",
                "runtime": name,
                "error": f'start container: write file /etc/hosts failed (exit 255)��Post "http://x/containers/{CID}/exec"',
            }
        ),
        json.dumps({"level": "ERROR", "msg": "other sandbox", "runtime": "lab-other-1"}),
    ]
    (root / "daemon.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    msg = base64.b64encode(b"sh: error while loading shared libraries: libc.so.6: Permission denied\n").decode()
    (root / "containerd" / "root" / "svc" / CID / f"{CID}-json.log").write_text(
        json.dumps({"stream": 2, "msg": msg}) + "\n" + json.dumps({"stream": 1, "msg": base64.b64encode(b"stdout\n").decode()}) + "\n"
    )
    return root


def test_diagnose_finds_the_sandbox_errors(tmp_path):
    lines = sbx_diag.diagnose(NAME, _state(tmp_path))
    assert lines[0].startswith("sbx: create sandbox failed") and "write file /etc/hosts failed" in lines[0]
    assert "�" not in lines[0] and "other sandbox" not in " ".join(lines)
    assert (
        lines[-1] == "container stderr (from the guest, untrusted): sh: error while loading shared libraries: libc.so.6: Permission denied"
    )


def test_diagnose_never_raises(tmp_path):
    assert sbx_diag.diagnose(NAME, tmp_path / "missing") == []
    assert sbx_diag.diagnose("", _state(tmp_path)) == []


def test_diagnose_reads_only_the_tail(tmp_path, monkeypatch):
    root = _state(tmp_path)
    with (root / "daemon.log").open("a") as fh:
        fh.write("x" * 5000 + "\n")
    monkeypatch.setattr(sbx_diag, "DAEMON_TAIL", 1000)
    assert sbx_diag.diagnose(NAME, root) == []


def test_failed_create_log_gets_the_daemon_lines(make_recipe, repo, tmp_path, monkeypatch):
    plan = runner.build_plan(make_recipe(), runs_dir=tmp_path / "runs", now=NOW, repo_root=repo)
    monkeypatch.setenv("LAB_SBX_STATE_DIR", str(_state(tmp_path, plan.sandbox)))
    fake = FakeSbx(plan, fail="create")
    assert runner.execute_plan(plan, execute=fake, log=lambda _: None) == runner.EXIT_RUN_FAILED
    log = (plan.run_dir / "logs" / "create.log").read_text()
    assert "--- sbx daemon ---" in log and "libc.so.6: Permission denied" in log


def test_tail_never_follows_a_symlink(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("do not read")
    link = tmp_path / "daemon.log"
    link.symlink_to(secret)
    assert sbx_diag._tail(link, 1000) == ""
    assert sbx_diag._tail(tmp_path, 1000) == ""  # a folder is not a log


def test_no_state_dir_off_macos(monkeypatch):
    monkeypatch.delenv("LAB_SBX_STATE_DIR", raising=False)
    monkeypatch.setattr(sbx_diag.sys, "platform", "linux")
    assert sbx_diag.state_dir() is None
    assert sbx_diag.diagnose("lab-x-1") == []
