"""lab models: the throwaway-sandbox model probe."""

import json
import subprocess
from pathlib import Path

import pytest

from lab import probe, sbx


class FakeRun:
    def __init__(self, fail=None, secret="openai-oauth", models=True):
        self.calls, self.fail, self.secret, self.models = [], fail, secret, models

    def __call__(self, argv, **kw):
        self.calls.append(list(argv))
        out = ""
        if argv[:3] == ["sbx", "secret", "ls"]:
            out = self.secret
        if "acp-bridge" in argv and self.models:
            t = next(a for a in argv if a.startswith("--transcript="))
            Path(t.split("=", 1)[1]).with_name("acp-models.json").write_text(
                json.dumps(
                    {"agent": "codex", "option": "model", "current": "gpt-6.2-sol", "values": [{"Value": "gpt-6.2-sol", "Name": "6.2 Sol"}]}
                )
            )
        rc = 1 if self.fail and any(self.fail in a for a in argv) else 0
        return subprocess.CompletedProcess(argv, rc, out, "")


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("BURNER_HOME", str(tmp_path / "bh"))


def names(run):
    out = []
    for c in run.calls:
        if c[:2] == ["sbx", "create"]:
            out.append("create")
        elif c[:3] == ["sbx", "policy", "allow"]:
            out.append("allow:" + c[-1])
        elif c[:3] == ["sbx", "policy", "rm"]:
            out.append("close:" + c[-1])
        elif c[:2] == ["sbx", "exec"]:
            out.append("exec")
        elif "acp-bridge" in c:
            out.append("probe")
        elif c[:2] == ["sbx", "rm"]:
            out.append("destroy")
        elif c[:3] == ["sbx", "secret", "ls"]:
            out.append("secret")
    return out


def test_probe_order_policy_and_cleanup(tmp_path):
    run = FakeRun()
    data = probe.probe("codex", "/usr/local/bin/burner", run=run)
    assert data["current"] == "gpt-6.2-sol"
    agent = sbx.AGENTS["codex"]
    install = [h for h in agent.acp_install_hosts if h not in agent.hosts]
    assert names(run) == [
        "secret",
        "create",
        "allow:" + ",".join(install),
        "allow:" + ",".join(agent.hosts),
        "exec",
        *["close:" + h for h in install],
        "probe",
        "destroy",
    ]
    create = run.calls[1]
    assert create[-2] == "codex" and "--kit" not in create  # the agent's built-in workload, no recipe kit
    bridge = next(c for c in run.calls if "acp-bridge" in c)
    assert "--probe" in bridge and not any(a.startswith("--prompt") for a in bridge)
    assert bridge[0] == "/usr/local/bin/burner"
    assert not list((tmp_path / "bh" / "tmp").iterdir())  # the temp workspace is removed


def test_probe_destroys_on_failure():
    run = FakeRun(fail="npm install")
    with pytest.raises(probe.ProbeError, match="acp-install failed"):
        probe.probe("codex", "/usr/local/bin/burner", run=run)
    assert names(run)[-1] == "destroy" and "probe" not in names(run)


def test_probe_no_model_list_still_destroys():
    run = FakeRun(models=False)
    with pytest.raises(probe.ProbeError, match="sent no model list"):
        probe.probe("codex", "/usr/local/bin/burner", run=run)
    assert names(run)[-1] == "destroy"


def test_missing_credential_shows_the_sign_in_hint_and_creates_nothing():
    run = FakeRun(secret="")
    with pytest.raises(probe.ProbeError) as e:
        probe.probe("codex", "/usr/local/bin/burner", run=run)
    assert e.value.code == probe.EXIT_PREFLIGHT
    assert "sbx run codex" in str(e.value)
    assert names(run) == ["secret"]


def test_refuses_without_bridge_or_acp():
    with pytest.raises(probe.ProbeError):
        probe.probe("codex", "", run=FakeRun())
    with pytest.raises(probe.ProbeError):
        probe.probe("nope", "/x/burner", run=FakeRun())


def test_claude_probe_installs_its_adapter():
    run = FakeRun()
    run_models = run.__call__

    def claude(argv, **kw):
        res = run_models(argv, **kw)
        if "acp-bridge" in argv:
            t = next(a for a in argv if a.startswith("--transcript="))
            p = Path(t.split("=", 1)[1]).with_name("acp-models.json")
            p.write_text(json.dumps({"agent": "claude", "values": []}))
        return res

    data = probe.probe("claude", "/usr/local/bin/burner", run=claude)
    assert data["agent"] == "claude"
    assert any("claude-agent-acp@" in " ".join(c) for c in run.calls)
