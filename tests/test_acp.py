"""ACP mode (--acp): plan shape, the bridge line protocol, host asks, R12."""

from __future__ import annotations

import datetime as dt
import json
import subprocess
import threading
import time
from pathlib import Path

import pytest

from lab import ask as ask_mod
from lab import runner, sbx

from .test_live import _evidence, _Exec

NOW = dt.datetime(2026, 11, 21, 10, 30, 0)


@pytest.fixture
def bridge_bin(tmp_path_factory, monkeypatch):
    path = tmp_path_factory.mktemp("bin") / "burner"
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(0o755)
    monkeypatch.setenv("BURNER_ACP_BRIDGE", str(path))
    return str(path)


def _plan(recipe, repo, tmp_path, **kw):
    return runner.build_plan(recipe, runs_dir=tmp_path / "runs", now=NOW, repo_root=repo, **kw)


def _argv(plan, name):
    return next(s.argv for s in plan.all_steps() if s.name == name)


def test_acp_plan_installs_the_server_in_the_install_window(make_recipe, repo, tmp_path, monkeypatch):
    monkeypatch.setenv("BURNER_ACP_BRIDGE", "/opt/burner")
    plan = _plan(make_recipe(), repo, tmp_path, agent_name="codex", acp=True, model="gpt-6-luna", permission="auto")
    names = [s.name for s in plan.all_steps()]
    install = _argv(plan, "policy-allow-install")[-1].split(",")
    for host in sbx.AGENTS["codex"].acp_install_hosts:
        assert host in install
        assert names.index("acp-install") < names.index(f"policy-close:{host}") < names.index("agent")
    assert names.index("tools") < names.index("acp-install")
    agent = _argv(plan, "agent")
    ws = str(plan.workspace)
    assert agent[:2] == ["/opt/burner", "acp-bridge"]
    assert "--agent=codex" in agent and "--permission=auto" in agent and "--model=gpt-6-luna" in agent
    assert f"--cwd={ws}" in agent
    assert f"--transcript={plan.run_dir / runner.ACP_TRANSCRIPT_RAW}" in agent
    tail = agent[agent.index("--") + 1 :]
    assert tail[:3] == ["sbx", "exec", "-i"]
    assert tail[tail.index("--") + 1 :] == list(sbx.AGENTS["codex"].acp)
    assert plan.acp


def test_headless_plan_is_unchanged_without_acp(make_recipe, repo, tmp_path):
    plan = _plan(make_recipe(), repo, tmp_path, agent_name="codex")
    names = [s.name for s in plan.all_steps()]
    assert "acp-install" not in names and not plan.acp
    assert "registry.npmjs.org:443" not in " ".join(" ".join(s.argv) for s in plan.all_steps())


@pytest.mark.parametrize(
    "kw, message",
    [
        ({"agent_name": "gemini", "acp": True}, "unknown agent"),
        ({"agent_name": "codex", "model": "gpt-6-luna"}, "--model needs --acp"),
        ({"agent_name": "codex", "acp": True, "model": "-rf"}, "invalid --model"),
        ({"agent_name": "codex", "acp": True, "permission": "yolo"}, "--permission"),
    ],
)
def test_acp_refusals(make_recipe, repo, tmp_path, kw, message):
    with pytest.raises(runner.Refused, match=message):
        _plan(make_recipe(), repo, tmp_path, **kw)


class _Bridge:
    """Stands in for AskBridge.ask_host."""

    def __init__(self, answer):
        self.answer, self.asked = answer, []

    def ask_host(self, ask_id, question, choices, allow_text):
        self.asked.append((ask_id, question, choices, allow_text))
        return self.answer


def test_bridge_lines_are_validated():
    emitted, logs, replies, skipped = [], [], [], [0]
    handle = runner._acp_line_handler("codex", lambda t, **f: emitted.append((t, f)), _Bridge("Allow"), logs.append, skipped)
    reply = replies.append
    handle(json.dumps({"t": "event", "type": "agent.message", "fields": {"text": "hi"}}), reply)
    handle(json.dumps({"t": "event", "type": "agent.tool", "fields": {"tool": "execute", "summary": "ls"}}), reply)
    # Unknown types, missing fields, non-string fields, junk: all dropped.
    handle(json.dumps({"t": "event", "type": "finding", "fields": {"id": "x"}}), reply)
    handle(json.dumps({"t": "event", "type": "agent.tool", "fields": {"tool": "x"}}), reply)
    handle(json.dumps({"t": "event", "type": "agent.message", "fields": {"text": 5}}), reply)
    handle("not json", reply)
    handle(json.dumps({"t": "ask", "id": "lab-123", "question": "q"}), reply)  # not an acp- id
    handle(json.dumps({"t": "log", "text": "model gpt-6-luna"}), reply)
    assert emitted == [
        ("agent.message", {"agent": "codex", "text": "hi"}),
        ("agent.tool", {"agent": "codex", "tool": "execute", "summary": "ls"}),
    ]
    assert skipped[0] == 5
    assert logs == ["    acp: model gpt-6-luna"]
    assert replies == []


def test_bridge_ask_goes_to_the_operator_and_back():
    replies = []
    bridge = _Bridge("Allow")
    handle = runner._acp_line_handler("codex", lambda *a, **k: None, bridge, lambda _: None, [0])
    handle(json.dumps({"t": "ask", "id": "acp-perm-1", "question": "Allow rm?", "choices": ["Allow", "Reject"]}), replies.append)
    for _ in range(100):
        if replies:
            break
        time.sleep(0.01)
    assert replies == [{"t": "answer", "id": "acp-perm-1", "value": "Allow"}]
    assert bridge.asked == [("acp-perm-1", "Allow rm?", ["Allow", "Reject"], False)]


def test_host_ask_is_answered_without_touching_the_workspace(tmp_path):
    ws, run = tmp_path / "ws", tmp_path / "run"
    ws.mkdir()
    run.mkdir()
    events = []
    bridge = ask_mod.AskBridge(ws, run, emit=lambda t, **f: events.append((t, f)))
    bridge.start()
    try:
        result = {}
        th = threading.Thread(target=lambda: result.setdefault("v", bridge.ask_host("acp-model", "Model?", ["a", "b"], False)))
        th.start()
        for _ in range(200):
            if "acp-model" in bridge.pending:
                break
            time.sleep(0.01)
        assert bridge.deliver("acp-model", "b")
        th.join(timeout=5)
        assert result["v"] == "b"
        assert not list((ws / ask_mod.ASK_DIR).glob("*.answer.json"))
        assert [t for t, _ in events] == ["ask", "answer"]
        assert bridge.report_asks()[0]["state"] == "user"
    finally:
        bridge.stop()
    assert bridge.forged == []


def test_host_ask_skip_mode_returns_none(tmp_path):
    (tmp_path / "ws").mkdir()
    (tmp_path / "run").mkdir()
    bridge = ask_mod.AskBridge(tmp_path / "ws", tmp_path / "run", on_ask={"mode": "skip"})
    bridge.start()
    try:
        assert bridge.ask_host("acp-turn-1", "More?", ["Finish"], True) is None
    finally:
        bridge.stop()


def test_acp_run_end_to_end_with_a_fake_bridge(make_recipe, repo, tmp_path, monkeypatch, bridge_bin):
    plan = _plan(make_recipe(), repo, tmp_path, agent_name="codex", acp=True)
    fake = _Exec(plan, evidence=_evidence())
    seen = {}
    secret = "sk-" + "a" * 40

    def acp_exec(argv, timeout, on_line, abort):
        seen["argv"] = argv
        fake(["sbx", "exec", "-p"], timeout)  # writes evidence like the headless fake
        (plan.run_dir / runner.ACP_TRANSCRIPT_RAW).write_text(json.dumps({"dir": "in", "raw": f"key {secret}"}) + "\n")
        on_line(json.dumps({"t": "event", "type": "agent.message", "fields": {"text": "working"}}), lambda _: None)
        return subprocess.CompletedProcess(argv, 0, "", "")

    code = runner.execute_plan(plan, execute=fake, log=lambda _: None, yes=True, acp_exec=acp_exec)
    assert code == runner.EXIT_OK
    assert seen["argv"][:3] == [bridge_bin, "acp-bridge", "--unattended"]
    assert not (plan.run_dir / runner.ACP_TRANSCRIPT_RAW).exists()
    redacted = (plan.run_dir / runner.ACP_TRANSCRIPT).read_text()
    assert secret not in redacted and "key " in redacted


def test_acp_run_needs_burner(make_recipe, repo, tmp_path, monkeypatch):
    monkeypatch.delenv("BURNER_ACP_BRIDGE", raising=False)
    plan = _plan(make_recipe(), repo, tmp_path, agent_name="codex", acp=True)
    fake = _Exec(plan, evidence=_evidence())
    with pytest.raises(runner.Refused, match="BURNER_ACP_BRIDGE"):
        runner.execute_plan(plan, execute=fake, log=lambda _: None, yes=True)
    assert fake.calls == []  # refused before any sandbox exists


def _prompt_of(plan):
    argv = _argv(plan, "agent")
    if plan.acp:
        return next(a.split("=", 1)[1] for a in argv if a.startswith("--prompt="))
    return argv[-1]


@pytest.mark.parametrize("acp", [False, True])
def test_prompt_names_scope_only_when_written_and_the_real_skill_path(make_recipe, repo, tmp_path, monkeypatch, acp):
    monkeypatch.setenv("BURNER_ACP_BRIDGE", "/opt/burner")
    recipe = make_recipe()
    (recipe.path / "skills" / "secrets-triage").mkdir(parents=True, exist_ok=True)
    (recipe.path / "skills" / "secrets-triage" / "SKILL.md").write_text("# s\n")
    plan = _plan(recipe, repo, tmp_path, agent_name="codex", acp=acp)
    prompt = _prompt_of(plan)
    assert plan.scope is None and ".lab/scope.json" not in prompt
    assert ".agents/skills/secrets-triage/SKILL.md" in prompt
    claude = _plan(recipe, repo, tmp_path, agent_name="claude")
    assert ".claude/skills/secrets-triage/SKILL.md" in _prompt_of(claude)


def test_prompt_names_scope_when_there_is_one(make_recipe, repo, tmp_path, scope_file):
    recipe = make_recipe("pentest", "pdemo")
    target = tmp_path / "t"
    target.mkdir()
    plan = _plan(recipe, repo, tmp_path, scope_path=str(scope_file), target=str(target))
    assert "Stay inside the scope in .lab/scope.json." in _prompt_of(plan)


SECRET = "Q51J77j7" + "abcDEF1234567890xyz"
AWS_SECRET = "RH16se6vABCDEFGHIJKLMNOPQRSTUVWXYZ012345"


def test_seen_secrets_and_fragments_never_reach_events_logs_or_transcript(make_recipe, repo, tmp_path, monkeypatch, bridge_bin):
    target = tmp_path / "target"
    (target / "tests").mkdir(parents=True)
    (target / "tests" / "test_exporter.py").write_text(f'API_KEY = "{SECRET}"\n')
    (target / "env.txt").write_text(f"aws_secret_access_key={AWS_SECRET}\n")
    plan = _plan(make_recipe(), repo, tmp_path, agent_name="codex", acp=True, target=str(target))
    fake = _Exec(plan, evidence=_evidence())
    events_file = plan.run_dir / "events.ndjson"

    def acp_exec(argv, timeout, on_line, abort):
        fake(["sbx", "exec", "-p"], timeout)
        shown = f"git log -S'{SECRET[:8]}' -S'{AWS_SECRET[:8]}' -- tests/"
        (plan.run_dir / runner.ACP_TRANSCRIPT_RAW).write_text(json.dumps({"raw": shown}) + "\n")
        on_line(json.dumps({"t": "event", "type": "agent.tool", "fields": {"tool": "execute", "summary": shown}}), lambda _: None)
        on_line(json.dumps({"t": "event", "type": "agent.message", "fields": {"text": f"found {SECRET}"}}), lambda _: None)
        on_line(json.dumps({"t": "log", "text": f"note {AWS_SECRET[:10]}"}), lambda _: None)
        return subprocess.CompletedProcess(argv, 0, f"stdout {SECRET[2:12]}", "")

    logs: list[str] = []
    code = runner.execute_plan(plan, execute=fake, log=logs.append, yes=True, events=str(events_file), acp_exec=acp_exec)
    assert code == runner.EXIT_OK
    kept = "\n".join(
        [
            events_file.read_text(),
            "\n".join(logs),
            (plan.run_dir / runner.ACP_TRANSCRIPT).read_text(),
            (plan.run_dir / "logs" / "agent.log").read_text(),
        ]
    )
    for fragment in (SECRET, SECRET[:8], SECRET[2:12], AWS_SECRET[:8], AWS_SECRET[:10]):
        assert fragment not in kept, fragment
    assert "[REDACTED:seen-secret]" in kept and "tests/" in kept


def test_transcript_is_redacted_even_when_the_agent_step_raises(make_recipe, repo, tmp_path, monkeypatch, bridge_bin):
    plan = _plan(make_recipe(), repo, tmp_path, agent_name="codex", acp=True)
    fake = _Exec(plan, evidence=_evidence())
    key = "sk-" + "b" * 40

    def acp_exec(argv, timeout, on_line, abort):
        (plan.run_dir / runner.ACP_TRANSCRIPT_RAW).write_text(f"key {key}\n")
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        runner.execute_plan(plan, execute=fake, log=lambda _: None, yes=True, acp_exec=acp_exec)
    assert not (plan.run_dir / runner.ACP_TRANSCRIPT_RAW).exists()
    kept = (plan.run_dir / runner.ACP_TRANSCRIPT).read_text()
    assert key not in kept and "key " in kept
    assert any(c[1:2] == ["rm"] for c in fake.calls), "sandbox not destroyed"


def test_a_second_ctrl_c_does_not_cut_the_teardown(make_recipe, repo, tmp_path):
    import os
    import signal

    plan = _plan(make_recipe(), repo, tmp_path)
    inner = _Exec(plan, evidence=_evidence())
    destroyed = []

    def fake(argv, timeout):
        if argv[1:2] == ["exec"] and ("-p" in argv or "--json" in argv):
            raise KeyboardInterrupt  # first Ctrl+C during the agent
        if argv[1:2] == ["rm"]:
            os.kill(os.getpid(), signal.SIGINT)  # second Ctrl+C during destroy
            time.sleep(0.05)
            destroyed.append(argv)
        return inner(argv, timeout)

    before = signal.getsignal(signal.SIGINT)
    with pytest.raises(KeyboardInterrupt):
        runner.execute_plan(plan, execute=fake, log=lambda _: None, yes=True, stream_exec=lambda a, t, _line, _abort: fake(a, t))
    assert destroyed, "destroy did not finish"
    assert signal.getsignal(signal.SIGINT) is before


@pytest.mark.parametrize("where", ["missing", "relative", "not-exec", "in-run-dir"])
def test_bridge_path_is_validated_before_any_sandbox(make_recipe, repo, tmp_path, monkeypatch, where):
    monkeypatch.setenv("BURNER_ACP_BRIDGE", "/opt/burner")
    plan = _plan(make_recipe(), repo, tmp_path, agent_name="codex", acp=True)
    plan.run_dir.mkdir(parents=True, exist_ok=True)
    path = {
        "missing": str(tmp_path / "nope"),
        "relative": "burner",
        "not-exec": str(tmp_path / "plain"),
        "in-run-dir": str(plan.run_dir / "burner"),
    }[where]
    for p in (tmp_path / "plain", plan.run_dir / "burner"):
        p.write_text("#!/bin/sh\n")
    (plan.run_dir / "burner").chmod(0o755)
    monkeypatch.setenv("BURNER_ACP_BRIDGE", path)
    fake = _Exec(plan, evidence=_evidence())
    with pytest.raises(runner.Refused, match="BURNER_ACP_BRIDGE"):
        runner.execute_plan(plan, execute=fake, log=lambda _: None, yes=True)
    assert fake.calls == []


def test_open_acp_asks_are_capped_runner_side():
    gate = threading.Event()

    class Slow:
        def ask_host(self, *a):
            gate.wait(5)
            return "x"

    replies = []
    handle = runner._acp_line_handler("codex", lambda *a, **k: None, Slow(), lambda _: None, [0])
    for i in range(runner.ACP_MAX_OPEN_ASKS + 1):
        handle(json.dumps({"t": "ask", "id": f"acp-perm-{i}", "question": "q", "choices": ["a"]}), replies.append)
    assert replies == [{"t": "answer", "id": f"acp-perm-{runner.ACP_MAX_OPEN_ASKS}", "value": None}]
    gate.set()


def test_agent_planted_seeds_cannot_erase_runner_records(make_recipe, repo, tmp_path, bridge_bin):
    plan = _plan(make_recipe(), repo, tmp_path, agent_name="codex", acp=True)
    host = "exfil1.attacker-c2.com"
    cve = "CVE-2026-12345"
    planted_secret = "zz9" + "Planted0Secret0Value"
    policy = json.dumps({"allowed": [], "blocked": [{"host": f"{host}:443"}]})
    fake = _Exec(plan, evidence=_evidence(), policy_log=policy)
    events_file = plan.run_dir / "events.ndjson"

    def acp_exec(argv, timeout, on_line, abort):
        fake(["sbx", "exec", "-p"], timeout)
        ev = json.loads((plan.workspace / "evidence" / "evidence.json").read_text())
        ev["summary"] = f"Checked {cve}; token {planted_secret}"
        (plan.workspace / "evidence" / "evidence.json").write_text(json.dumps(ev))
        art = plan.workspace / "evidence" / "artifacts"
        art.mkdir(parents=True, exist_ok=True)
        (art / "gitleaks.json").write_text(json.dumps([{"secret": host, "value": cve, "match": host, "Secret": planted_secret}]))
        time.sleep(2.5)  # let the watcher harvest the artifacts
        on_line(json.dumps({"t": "event", "type": "agent.message", "fields": {"text": f"saw {planted_secret}"}}), lambda _: None)
        return subprocess.CompletedProcess(argv, 0, "", "")

    code = runner.execute_plan(plan, execute=fake, log=lambda _: None, yes=True, events=str(events_file), acp_exec=acp_exec)
    assert code in (runner.EXIT_OK, runner.EXIT_GATE_FAILED)
    assert host in (plan.run_dir / "policy-log.json").read_text()
    events = events_file.read_text()
    assert f'"host": "{host}' in events  # the blocked event is intact
    assert planted_secret not in events  # the agent's own text is masked
    report = (plan.run_dir / "report.json").read_text()
    assert cve in report


def test_seed_masking_is_linear_and_capped():
    from lab import evidence

    seeds = evidence.Seeds()
    for i in range(5000):
        seeds.add(f"A{i:05d}" + "x7" * 70, agent=True)  # over length: refused
        seeds.add(f"S{i:05d}q" + "k9" * 55, agent=True)
    assert len(seeds.agent.values) == evidence.MAX_AGENT_SEEDS
    assert all(len(v) <= evidence.MAX_SEED_LEN for v in seeds.agent.values)
    text = ("tok" + "a1B2c3D4e5 " * 10 + "\n") * 9000  # ~1 MB
    start = time.monotonic()
    seeds.mask(text, agent=True)
    assert time.monotonic() - start < 1.0
    sample = next(iter(seeds.agent.values))
    masked, n = seeds.mask(f"x {sample[3:15]} y", agent=True)
    assert n == 1 and sample[3:15] not in masked
    assert seeds.mask(f"x {sample[3:15]} y")[1] == 0  # agent seeds stay out of runner text


def test_a_hung_destroy_is_bounded_and_leaves_a_hint(make_recipe, repo, tmp_path):
    plan = _plan(make_recipe(), repo, tmp_path)
    inner = _Exec(plan, evidence=_evidence())
    seen = {}

    def fake(argv, timeout):
        if argv[1:2] == ["rm"]:
            seen["timeout"] = timeout
            raise subprocess.TimeoutExpired(argv, timeout)
        return inner(argv, timeout)

    logs: list[str] = []
    runner.execute_plan(plan, execute=fake, log=logs.append, yes=True)
    assert seen["timeout"] == runner.TEARDOWN_TIMEOUT
    assert any(f"sbx rm --force {plan.sandbox}" in line for line in logs)


def test_codex_model_goes_into_the_adapter_session_config(make_recipe, repo, tmp_path, monkeypatch):
    monkeypatch.setenv("BURNER_ACP_BRIDGE", "/opt/burner")
    plan = _plan(make_recipe(), repo, tmp_path, agent_name="codex", acp=True, model="gpt-7-custom")
    agent = plan.agent_step.argv
    assert "--env" in agent and 'CODEX_CONFIG={"model":"gpt-7-custom"}' in agent
    assert "--model=gpt-7-custom" in agent


def test_claude_model_goes_through_set_config_option_only(make_recipe, repo, tmp_path, monkeypatch):
    monkeypatch.setenv("BURNER_ACP_BRIDGE", "/opt/burner")
    plan = _plan(make_recipe(), repo, tmp_path, agent_name="claude", acp=True, model="claude-mythos-5-2")
    agent = plan.agent_step.argv
    assert "--model=claude-mythos-5-2" in agent
    assert not any(a.startswith("CODEX_CONFIG") or a.startswith("ANTHROPIC_MODEL") for a in agent)


def test_tool_events_keep_id_detail_and_status(tmp_path):
    from lab import events as events_mod
    from lab import jsonschema_lite

    out = tmp_path / "events.ndjson"
    w = events_mod.EventWriter(out, "20261122-194453-secrets-scan")
    handle = runner._acp_line_handler("claude", w.emit, _Bridge("Allow"), lambda _m: None, [0])
    fields = {"tool": "execute", "summary": "Run gitleaks", "detail": "gitleaks git .", "id": "toolu_01K7", "status": "completed"}
    handle(json.dumps({"t": "event", "type": "agent.tool", "fields": fields}), lambda _r: None)
    handle(
        json.dumps({"t": "event", "type": "agent.tool", "fields": {"tool": "output", "summary": "a\nb", "id": "toolu_01K7"}}),
        lambda _r: None,
    )
    # A bad id or status is dropped, the line is kept.
    bad = {"tool": "execute", "summary": "x", "id": "../../etc", "status": "exploded"}
    handle(json.dumps({"t": "event", "type": "agent.tool", "fields": bad}), lambda _r: None)
    w.close()
    evs = [json.loads(line) for line in out.read_text().splitlines()]
    assert evs[0]["id"] == "toolu_01K7" and evs[0]["detail"] == "gitleaks git ." and evs[0]["status"] == "completed"
    assert evs[1]["summary"] == "a\nb"
    assert "id" not in evs[2] and "status" not in evs[2]
    schema = json.loads((Path(runner.__file__).parent / "schema" / "events.schema.json").read_text())
    for e in evs:
        sub = dict(schema["$defs"][e["type"]])
        sub["$defs"] = schema["$defs"]
        assert not jsonschema_lite.validate(e, sub), e


def test_model_default_keeps_the_agent_default(make_recipe, repo, tmp_path, monkeypatch):
    monkeypatch.setenv("BURNER_ACP_BRIDGE", "/opt/burner")
    recipe = make_recipe()
    plan = _plan(recipe, repo, tmp_path, agent_name="codex", acp=True, model="default")
    agent = plan.agent_step.argv
    assert "--model=default" in agent
    assert not any(a.startswith("CODEX_CONFIG") for a in agent)
    plan = _plan(recipe, repo, tmp_path, agent_name="codex", interactive=True, model="default")
    assert "-m" not in plan.agent_step.argv and "default" not in plan.agent_step.argv
