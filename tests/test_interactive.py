"""--interactive: the agent's own TUI on the operator's terminal, then collect."""

from __future__ import annotations

import datetime as dt
import json

import pytest

from lab import ask as ask_mod
from lab import jsonschema_lite, runner

from .test_live import _evidence, _Exec

NOW = dt.datetime(2026, 11, 21, 10, 30, 0)
SCHEMA = json.loads((runner.Path(__file__).resolve().parent.parent / "lab" / "schema" / "events.schema.json").read_text())


def _plan(recipe, repo, tmp_path, **kw):
    return runner.build_plan(recipe, runs_dir=tmp_path / "runs", now=NOW, repo_root=repo, **kw)


def test_interactive_plan_opens_the_agent_tui_with_the_task(make_recipe, repo, tmp_path):
    plan = _plan(make_recipe(), repo, tmp_path, agent_name="codex", interactive=True, model="gpt-6-luna")
    argv = next(s.argv for s in plan.all_steps() if s.name == "agent")
    assert argv[:3] == ["sbx", "exec", "-it"]
    cmd = argv[argv.index("--") + 1 :]
    assert cmd[:2] == ["codex", "--dangerously-bypass-approvals-and-sandbox"]
    assert cmd[2:4] == ["-m", "gpt-6-luna"] and "AGENTS.md" in cmd[-1]
    assert plan.interactive and not plan.acp


@pytest.mark.parametrize(
    ("kw", "message"),
    [({"acp": True, "interactive": True}, "pick one"), ({"model": "gpt-6"}, "needs --acp or --interactive")],
)
def test_interactive_refusals(make_recipe, repo, tmp_path, kw, message):
    with pytest.raises(runner.Refused, match=message):
        _plan(make_recipe(), repo, tmp_path, agent_name="codex", **kw)


def test_interactive_run_hands_off_then_collects(make_recipe, repo, tmp_path, monkeypatch):
    plan = _plan(make_recipe(), repo, tmp_path, agent_name="codex", interactive=True)
    fake = _Exec(plan, evidence=_evidence())
    asked = {}

    def ask_host(self, ask_id, question, choices, allow_text, exempt_timeout_s=None):
        asked["id"], asked["choices"] = ask_id, choices
        asked["timeout"] = exempt_timeout_s
        fake(["sbx", "exec", "-p"], None)  # the operator's session writes evidence
        return "done"

    monkeypatch.setattr(ask_mod.AskBridge, "ask_host", ask_host)
    events_file = plan.run_dir / "events.ndjson"
    code = runner.execute_plan(plan, execute=fake, log=lambda _: None, events=str(events_file))
    assert code == runner.EXIT_OK
    assert asked == {"id": runner.INTERACTIVE_ASK, "choices": ["done"], "timeout": plan.interactive_timeout}
    assert plan.interactive_timeout > 0
    events = [json.loads(line) for line in events_file.read_text().splitlines()]
    handoff = next(e for e in events if e["type"] == "handoff")
    assert handoff["name"] == "agent" and handoff["argv"][:3] == ["sbx", "exec", "-it"]
    sub = dict(SCHEMA["$defs"]["handoff"], **{"$defs": SCHEMA["$defs"]})
    assert jsonschema_lite.validate(handoff, sub) == []
    assert not any(c[:3] == ["sbx", "exec", "-it"] for c in fake.calls), "the runner never runs the TUI itself"


def test_interactive_without_an_operator_fails(make_recipe, repo, tmp_path, monkeypatch):
    plan = _plan(make_recipe(), repo, tmp_path, agent_name="codex", interactive=True)
    fake = _Exec(plan, evidence=_evidence())
    monkeypatch.setattr(ask_mod.AskBridge, "ask_host", lambda *a, **kw: None)
    assert runner.execute_plan(plan, execute=fake, log=lambda _: None) == runner.EXIT_RUN_FAILED


@pytest.mark.parametrize(("on_ask", "yes"), [("skip", False), ("fail", False), (None, True)])
def test_interactive_refuses_unattended_modes(make_recipe, repo, tmp_path, on_ask, yes):
    plan = _plan(make_recipe(), repo, tmp_path, agent_name="codex", interactive=True)
    fake = _Exec(plan, evidence=_evidence())
    with pytest.raises(runner.Refused, match="needs an operator"):
        runner.execute_plan(plan, execute=fake, log=lambda _: None, on_ask=on_ask, yes=yes)
    assert fake.calls == []


def test_interactive_ask_ignores_the_on_ask_timeout(make_recipe, repo, tmp_path, monkeypatch):
    import threading
    import time

    plan = _plan(make_recipe(), repo, tmp_path, agent_name="codex", interactive=True)
    fake = _Exec(plan, evidence=_evidence())
    bridges = []
    real_init = ask_mod.AskBridge.__init__

    def capture(self, *a, **kw):
        real_init(self, *a, **kw)
        bridges.append(self)

    monkeypatch.setattr(ask_mod.AskBridge, "__init__", capture)
    result = {}
    t = threading.Thread(
        target=lambda: result.setdefault("code", runner.execute_plan(plan, execute=fake, log=lambda _: None, on_ask="timeout=1s"))
    )
    t.start()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not (bridges and runner.INTERACTIVE_ASK in bridges[0].pending):
        time.sleep(0.05)
    assert bridges and runner.INTERACTIVE_ASK in bridges[0].pending
    time.sleep(2.5)  # past the 1 s --on-ask timeout
    assert runner.INTERACTIVE_ASK in bridges[0].pending, "the agent-tui ask expired under the live session"
    assert not any(c[1:2] == ["rm"] for c in fake.calls), "the sandbox was destroyed while the TUI was open"
    fake(["sbx", "exec", "-p"], None)  # the session writes evidence
    assert bridges[0].deliver(runner.INTERACTIVE_ASK, "done")
    t.join(timeout=20)
    assert result.get("code") == runner.EXIT_OK
