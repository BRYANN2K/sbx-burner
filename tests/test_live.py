"""Tests for the live-run support: events, sanitization, ask bridge."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from lab import agent_stream, jsonschema_lite, runner, sanitize
from lab import ask as ask_mod
from lab import events as events_mod

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / "lab" / "schema" / "events.schema.json").read_text(encoding="utf-8"))
LAB_ASK = ROOT / "lab" / "kit" / "lab-ask"


class _Null:
    def write(self, _):
        return 0

    def flush(self):
        pass


def _quiet_writer():
    return events_mod.EventWriter("-", "r", stream=_Null())


def check(event):
    sub = dict(SCHEMA["$defs"][event["type"]])
    sub["$defs"] = SCHEMA["$defs"]
    return jsonschema_lite.validate(event, sub)


def _plan(recipe, repo, tmp_path, **kw):
    return runner.build_plan(recipe, runs_dir=tmp_path / "runs", now=dt.datetime(2026, 11, 21, 10, 30), repo_root=repo, **kw)


def _exec_ok(argv, timeout):
    return subprocess.CompletedProcess(argv, 0, "", "")


class _Exec:
    """Records argv; plays steps like test_runner.FakeSbx (evidence, policy log)."""

    def __init__(self, plan, evidence=None, policy_log='{"allowed": [], "blocked": [{"host": "example.com"}]}', sleep=0.0, agent_stdout=""):
        self.plan, self.calls = plan, []
        self.evidence, self.policy_log, self.sleep = evidence, policy_log, sleep
        self.agent_stdout = agent_stdout

    def __call__(self, argv, timeout):
        self.calls.append(argv)
        if "curl" in argv:
            return subprocess.CompletedProcess(argv, 22, "", "")  # egress probes must fail
        if argv[1:3] == ["policy", "log"]:
            return subprocess.CompletedProcess(argv, 0, self.policy_log, "")
        if "-p" in argv or "--json" in argv:
            if self.evidence is not None:
                ev = self.plan.workspace / "evidence"
                (ev / "artifacts").mkdir(parents=True, exist_ok=True)
                for finding in self.evidence.get("findings") or []:
                    for artifact in (finding.get("proof") or {}).get("artifacts") or []:
                        (ev / artifact).write_text("proof output\n", encoding="utf-8")
                (ev / "evidence.json").write_text(json.dumps(self.evidence), encoding="utf-8")
            if self.sleep:
                time.sleep(self.sleep)
            return subprocess.CompletedProcess(argv, 0, self.agent_stdout, "")
        return subprocess.CompletedProcess(argv, 0, "", "")


def _evidence(findings=None):
    return {
        "schema_version": "1",
        "recipe": "devsecops/demo",
        "summary": "Ran the tool.",
        "tools_run": [{"name": "t", "command": "t .", "exit_code": 0}],
        "findings": findings or [],
        "hypotheses": [],
        "artifacts": [],
    }


def _finding():
    return {
        "id": "D-001",
        "title": "Demo finding",
        "severity": "high",
        "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 8.0},
        "cwe": "CWE-000",
        "target": "demo-app",
        "description": "A finding proven during the unit test.",
        "proof": {"poc": "run it", "artifacts": ["artifacts/x.txt"]},
    }


# ---------------------------------------------------------------- sanitize


def test_clean_text_strips_terminal_control():
    osc52 = "\x1b]52;c;aGVsbG8=\x07"
    cursor = "\x1b[2J\x1b[1;1H"
    dcs = "\x1bPq payload \x1b\\"
    sgr = "\x1b[1;31m"
    assert sanitize.clean_text(f"a{osc52}b{cursor}c{dcs}d{sgr}e") == "abcde"
    assert sanitize.clean_text("ok\x1b]52;c;AAAA") == "ok", "unterminated OSC strips to the end"
    assert sanitize.clean_text("ok\x1bPq payload") == "ok", "unterminated DCS strips to the end"
    assert sanitize.clean_text("del\x7f c1\x85 c1b\x9b") == "del c1 c1b"
    assert sanitize.clean_text("cr\rbel\x07") == "crbel"
    assert sanitize.clean_text("keep\n\ttab") == "keep\n\ttab"
    assert (
        check(
            {
                "schema_version": "1",
                "type": "agent.message",
                "seq": 0,
                "ts": "2026-11-21T10:30:00Z",
                "run_id": "r",
                "text": sanitize.clean_text(f"x{osc52}{cursor}{dcs}y"),
            }
        )
        == []
    )


def test_clean_text_caps_and_marks():
    out = sanitize.clean_text("x" * 5000)
    assert len(out) == 4096 and out.endswith("…")
    assert len(sanitize.clean_text("y" * 300, 256)) == 256


def test_clean_choices_caps():
    choices = sanitize.clean_choices(["c"] * 100)
    assert len(choices) == 64
    assert sanitize.clean_choices(["x" * 600]) == ["x" * 511 + "…"]
    assert sanitize.clean_choices("not-a-list") == []


# ---------------------------------------------------------------- events


def test_writer_emit_validates_against_schema(tmp_path):
    path = tmp_path / "events.ndjson"
    w = events_mod.EventWriter(path, "run-1")
    w.emit("step", name="create", status="start")
    w.emit("step", name="agent", status="ok", detail="exit 0")
    w.emit("agent.message", agent="claude", text="hello")
    w.emit("agent.tool", agent="claude", tool="Bash", summary="curl -s x")
    w.emit("finding", id="F-1", title="t", status="candidate", severity="high")
    w.emit("blocked", host="example.com")
    w.emit("ask", ask_id="a1", question="q?", choices=["y", "n"], allow_text=False, timeout_s=30)
    w.emit("answer", ask_id="a1", by="user", value="y")
    w.emit("done", exit_code=0, status="completed", report="runs/run-1/report.md")
    w.close()
    events = [json.loads(line) for line in path.read_text().splitlines()]
    assert [e["seq"] for e in events] == list(range(len(events)))
    assert all(e["run_id"] == "run-1" and e["schema_version"] == "1" for e in events)
    for event in events:
        assert check(event) == [], event


def test_writer_sanitizes_and_redacts(tmp_path):
    token = "ghp_" + "A" * 36
    key = "sk-ant-" + "B" * 30
    path = tmp_path / "events.ndjson"
    w = events_mod.EventWriter(path, "run-1")
    w.emit("agent.message", agent="claude", text=f"esc \x1b[2J osc \x1b]52;c;eA==\x07 token {token} key {key}")
    w.emit("agent.tool", agent="claude", tool="Bash", summary=f"curl {token}")
    w.emit("ask", ask_id="a1", question="x" * 5000, choices=["\x1b[2Jevil"] * 80, allow_text=True, timeout_s=0)
    w.close()
    events = [json.loads(line) for line in path.read_text().splitlines()]
    raw = path.read_text()
    assert token not in raw and key not in raw and "\x1b" not in raw
    assert events[2]["question"] == "x" * 4095 + "…"
    assert len(events[2]["choices"]) == 64 and events[2]["choices"][0] == "evil"
    for event in events:
        assert check(event) == [], event


# ------------------------------------------------------------ agent_stream


CLAUDE_STREAM = [
    '{"type":"system","subtype":"init","session_id":"s1"}',
    '{"type":"assistant","message":{"content":[{"type":"text","text":"I will probe auth."},'
    '{"type":"tool_use","name":"Bash","input":{"command":"curl -s http://api | jq ."}}]}}',
    '{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Read","input":{"file_path":"/app/api.py"}}]}}',
    '{"type":"user","message":{"content":[{"type":"tool_result","content":"ok"}]}}',
    '{"type":"result","result":"done"}',
    "not json at all",
]


def test_claude_stream_normalizes_and_counts():
    emitted, skipped = [], 0
    for line in CLAUDE_STREAM:
        events, n = agent_stream.from_claude_stream_json(line)
        emitted += events
        skipped += n
    types = [t for t, _ in emitted]
    assert types == ["agent.message", "agent.tool", "agent.tool"]
    assert emitted[1][1]["tool"] == "Bash" and emitted[1][1]["summary"].startswith("curl -s")
    assert emitted[2][1]["summary"] == "/app/api.py"
    assert skipped == 4
    w = _quiet_writer()
    for t, f in emitted:
        assert check(w.emit(t, **f)) == []


CODEX_STREAM = [
    '{"type":"thread.started","thread_id":"t"}',
    '{"type":"turn.started"}',
    '{"type":"item.completed","item":{"type":"agent_message","text":"scanning now"}}',
    '{"type":"item.completed","item":{"type":"command_execution","command":"semgrep --config r ."}}',
    '{"type":"item.completed","item":{"type":"mystery_item","x":1}}',
    '{"type":"turn.completed","usage":{"input_tokens":3}}',
    "{broken",
]


def test_codex_stream_normalizes_and_counts():
    emitted, skipped = [], 0
    for line in CODEX_STREAM:
        events, n = agent_stream.from_codex_json(line)
        emitted += events
        skipped += n
    types = [t for t, _ in emitted]
    assert types == ["agent.message", "agent.tool"]
    assert emitted[1][1]["summary"].startswith("semgrep")
    assert skipped == 5


def test_agent_stream_normalizers_schema_valid():
    w = _quiet_writer()
    for line in CLAUDE_STREAM + CODEX_STREAM:
        for normalize in (agent_stream.from_claude_stream_json, agent_stream.from_codex_json):
            for t, f in normalize(line)[0]:
                assert check(w.emit(t, **f)) == []


# ------------------------------------------------------------ ask bridge


def _unix_connect(run_dir):
    """Connect to run_dir/control.sock through fchdir: sun_path is ~104 bytes."""
    old_cwd = os.open(".", os.O_RDONLY)
    run_fd = os.open(run_dir, os.O_RDONLY)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        os.fchdir(run_fd)
        s.connect("control.sock")
    finally:
        os.fchdir(old_cwd)
        os.close(run_fd)
        os.close(old_cwd)
    return s


def _bridge(tmp_path, **kw):
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    run_dir = tmp_path / "run"
    run_dir.mkdir(exist_ok=True)
    emitted = []
    bridge = ask_mod.AskBridge(ws, run_dir, emit=lambda *a, **f: emitted.append((a[0], f)), **kw)
    return bridge, ws, run_dir, emitted


def _write_question(ws, ask_id="a1", question="proceed?", choices=None, timeout_s=0):
    (ws / ".lab" / "ask").mkdir(parents=True, exist_ok=True)
    payload = {"ask_id": ask_id, "question": question, "choices": choices or [], "allow_text": not choices, "timeout_s": timeout_s}
    (ws / ".lab" / "ask" / f"{ask_id}.json").write_text(json.dumps(payload), encoding="utf-8")


def test_control_socket_contract(tmp_path):
    bridge, ws, run_dir, emitted = _bridge(tmp_path)
    _write_question(ws, "a1", "pick", choices=["yes", "no"])
    bridge.start()
    try:
        sock_path = run_dir / "control.sock"
        assert stat.S_ISSOCK(sock_path.stat().st_mode)
        assert stat.S_IMODE(sock_path.stat().st_mode) == 0o600
        deadline = time.monotonic() + 3
        while "a1" not in bridge.pending and time.monotonic() < deadline:
            time.sleep(0.05)
        assert "a1" in bridge.pending

        def send(payload):
            with _unix_connect(run_dir) as s:
                s.sendall((json.dumps(payload) + "\n").encode())
                return json.loads(s.makefile().readline())

        assert send({"ask_id": "ghost", "value": "no"})["error"]
        assert send({"ask_id": "a1", "value": "yes"}) == {"ok": True}
        assert send({"ask_id": "a1", "value": "again"})["error"]
        assert (ws / ".lab" / "ask" / "a1.answer.json").exists()
        assert bridge.forged == []
        events = [t for t, _ in emitted]
        assert "ask" in events and "answer" in events
        log = (run_dir / "asks.jsonl").read_text()
        assert '"event": "ask"' in log and '"by": "user"' in log
    finally:
        bridge.stop()


def test_control_socket_refuses_bad_paths_and_oversize(tmp_path):
    bridge, ws, run_dir, _ = _bridge(tmp_path)
    target = run_dir / "control.sock"
    target.write_text("occupied")
    with pytest.raises(ask_mod.AskError):
        bridge.start()
    target.unlink()
    target.symlink_to("/tmp/elsewhere")
    with pytest.raises(ask_mod.AskError):
        bridge.start()
    target.unlink()

    bridge, ws, run_dir, _ = _bridge(tmp_path)
    _write_question(ws, "a2")
    bridge.start()
    try:
        deadline = time.monotonic() + 3
        while "a2" not in bridge.pending and time.monotonic() < deadline:
            time.sleep(0.05)
        with _unix_connect(run_dir) as s:
            s.sendall((json.dumps({"ask_id": "a2", "value": "x" * 5000}) + "\n").encode())
            assert "error" in s.makefile().readline()
    finally:
        bridge.stop()


def test_answers_dir_roundtrip_and_lab_ask(tmp_path):
    answers = tmp_path / "answers"
    answers.mkdir()
    bridge, ws, run_dir, emitted = _bridge(tmp_path, answers=answers)
    bridge.start()
    try:
        env = dict(os.environ, LAB_WORKSPACE=str(ws))
        proc = subprocess.Popen(
            [sys.executable, str(LAB_ASK), "continue?", "--timeout", "15"],
            cwd=ws,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        ask_dir = ws / ".lab" / "ask"
        question, deadline = None, time.monotonic() + 8
        while time.monotonic() < deadline:
            files = [f for f in ask_dir.glob("*.json") if not f.name.endswith(".answer.json")]
            if files:
                question = files[0].stem
                break
            time.sleep(0.1)
        assert question, "lab-ask never wrote its question"
        (answers / question).write_text("yes, proceed", encoding="utf-8")
        out, err = proc.communicate(timeout=10)
        assert proc.returncode == 0 and out.strip() == "yes, proceed"
        record = bridge.report_asks()[0]
        assert record["state"] == "user" and record["answers"][0]["value"] == "yes, proceed"
    finally:
        bridge.stop()


def test_lab_ask_own_timeout_exits_3(tmp_path):
    env = dict(os.environ, LAB_WORKSPACE=str(tmp_path))
    proc = subprocess.run(
        [sys.executable, str(LAB_ASK), "anyone?", "--timeout", "1"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert proc.returncode == 3 and proc.stdout == ""


def test_on_ask_skip_answers_exit_3(tmp_path):
    bridge, ws, run_dir, emitted = _bridge(tmp_path, on_ask={"mode": "skip"})
    bridge.start()
    try:
        env = dict(os.environ, LAB_WORKSPACE=str(ws))
        proc = subprocess.run(
            [sys.executable, str(LAB_ASK), "proceed?", "--timeout", "15"],
            cwd=ws,
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
        )
        assert proc.returncode == 3
        record = bridge.report_asks()[0]
        assert record["state"] == "skip" and record["answers"][0]["by"] == "skip"
        assert any(t == "answer" and f.get("by") == "skip" for t, f in emitted)
    finally:
        bridge.stop()


def test_forged_answer_flagged_never_delivered(tmp_path):
    bridge, ws, run_dir, emitted = _bridge(tmp_path)
    _write_question(ws, "forge1")
    bridge.start()
    try:
        deadline = time.monotonic() + 3
        while "forge1" not in bridge.pending and time.monotonic() < deadline:
            time.sleep(0.05)
        # The agent writes its own answer file - a forgery.
        (ws / ".lab" / "ask" / "forge1.answer.json").write_text('{"ask_id": "forge1", "value": "yes"}', encoding="utf-8")
        deadline = time.monotonic() + 3
        while not bridge.forged and time.monotonic() < deadline:
            time.sleep(0.05)
        assert bridge.forged == ["forge1.answer.json"]
        record = bridge.report_asks()[0]
        assert record["state"] == "asked" and record["answers"] == [], "a forged file is never a delivered answer"
        assert any(t == "answer" and f.get("by") == "forged" for t, f in emitted)
        log = (run_dir / "asks.jsonl").read_text()
        assert '"event": "forged"' in log and '"by": "user"' not in log
    finally:
        bridge.stop()


def test_tampered_answer_file_flagged_host_value_kept(tmp_path):
    bridge, ws, run_dir, emitted = _bridge(tmp_path)
    _write_question(ws, "t1")
    bridge.start()
    try:
        deadline = time.monotonic() + 3
        while "t1" not in bridge.pending and time.monotonic() < deadline:
            time.sleep(0.05)
        assert bridge.deliver("t1", "no")
        answer = ws / ".lab" / "ask" / "t1.answer.json"
        # The agent overwrites the delivered answer: bytes differ, inode is new.
        answer.write_text('{"ask_id": "t1", "value": "yes"}\n', encoding="utf-8")
        deadline = time.monotonic() + 3
        while not bridge.forged and time.monotonic() < deadline:
            time.sleep(0.05)
        assert bridge.forged == ["t1.answer.json"]
        record = bridge.report_asks()[0]
        assert record["answers"][0]["value"] == "no", "the report value is the host's, not the file's"
        assert any(t == "answer" and f.get("by") == "forged" for t, f in emitted)
        # A deleted answer file is tampering too.
        answer.unlink()
        bridge._scan_forged()
        assert bridge.forged.count("t1.answer.json") >= 1
    finally:
        bridge.stop()


# ------------------------------------------------------ runner integration


def test_operator_notes_plan_task_and_report(make_recipe, repo, tmp_path, scope_file):
    recipe = make_recipe("pentest", "pdemo")
    secret = "sk-ant-" + "z" * 30
    notes = [{"source": "prompt", "text": f"watch out for {secret}"}, {"source": "file:n.md", "text": "note two"}]
    target = tmp_path / "targetdir"
    target.mkdir()
    kw = {"scope_path": str(scope_file), "target": str(target)}
    plan = _plan(recipe, repo, tmp_path, operator_notes=notes, **kw)
    plain = _plan(recipe, repo, tmp_path, **kw)
    assert [s.argv for s in plan.all_steps()] == [s.argv for s in plain.all_steps()]
    assert plan.policy == plain.policy
    runner.prepare_workspace(plan, repo_root=repo)
    task = (plan.workspace / "TASK.md").read_text()
    assert task.index("## Scope") < task.index("## Operator notes") < task.index("## Evidence rules")
    assert secret not in task and "watch out for sk-" in task  # redacted
    fake = _Exec(plan, evidence=_evidence())
    code = runner.execute_plan(plan, execute=fake, log=lambda _: None)
    assert code == runner.EXIT_OK
    meta = json.loads((plan.run_dir / "report.json").read_text())["run"]
    assert [n["source"] for n in meta["operator_notes"]] == ["prompt", "file:n.md"]
    assert meta["operator_notes"][0]["sha256"] == hashlib.sha256(notes[0]["text"].encode()).hexdigest()
    assert secret not in meta["operator_notes"][0]["text"]
    assert meta["asks"] == []


def test_events_dash_stdout_only_ndjson(make_recipe, repo, tmp_path, capsys):
    plan = _plan(make_recipe(), repo, tmp_path)
    fake = _Exec(plan, evidence=_evidence())
    code = runner.execute_plan(plan, execute=fake, events="-")
    assert code == runner.EXIT_OK
    out = capsys.readouterr()
    lines = [line for line in out.out.splitlines() if line.strip()]
    assert lines, "no events on stdout"
    for line in lines:
        event = json.loads(line)
        assert check(event) == [], event
        assert event["run_id"] == plan.run_id
    assert lines[-1].startswith('{"schema_version": "1", "type": "done"')
    assert "==>" in out.err, "human log lines belong on stderr"


def test_events_file_refused_inside_workspace(make_recipe, repo, tmp_path):
    plan = _plan(make_recipe(), repo, tmp_path)
    fake = _Exec(plan)
    with pytest.raises(runner.Refused, match="workspace"):
        runner.execute_plan(plan, execute=fake, events="workspace/evil.ndjson", log=lambda _: None)
    with pytest.raises(runner.Refused):
        runner.execute_plan(plan, execute=fake, events="../outside.ndjson", log=lambda _: None)


def test_run_events_sequence_and_report(make_recipe, repo, tmp_path):
    plan = _plan(make_recipe(), repo, tmp_path)
    fake = _Exec(plan, evidence=_evidence(findings=[_finding()]), sleep=0.8)
    code = runner.execute_plan(plan, execute=fake, events="events.ndjson", log=lambda _: None)
    assert code == runner.EXIT_OK
    assert stat.S_IMODE(plan.run_dir.stat().st_mode) == 0o700
    events = [json.loads(line) for line in (plan.run_dir / "events.ndjson").read_text().splitlines()]
    for event in events:
        assert check(event) == [], event
    types = [e["type"] for e in events]
    assert types[-1] == "done"
    names = [(e["name"], e["status"]) for e in events if e["type"] == "step"]
    assert ("create", "start") in names and ("agent", "ok") in names and ("report", "ok") in names
    findings = [e for e in events if e["type"] == "finding"]
    assert {f["status"] for f in findings} == {"candidate", "proven"}
    assert types.index("finding") < len(types) - 1
    blocked = [e for e in events if e["type"] == "blocked"]
    assert [b["host"] for b in blocked] == ["example.com"]
    done = events[-1]
    assert done["exit_code"] == 0 and done["report"].endswith("report.md")
    meta = json.loads((plan.run_dir / "report.json").read_text())["run"]
    assert meta["asks"] == [] and "forged_answers" not in meta


def test_agent_stream_lines_become_events(make_recipe, repo, tmp_path):
    plan = _plan(make_recipe(), repo, tmp_path)
    secret = "ghp_" + "K" * 36
    stream = (
        '{"type":"assistant","message":{"content":[{"type":"text","text":"probing the API now"},'
        '{"type":"tool_use","name":"Bash","input":{"command":"curl -s http://api/users"}}]}}\n'
        '{"type":"result","result":"done"}\n'
        f"plain text with {secret}\n"
    )
    fake = _Exec(plan, evidence=_evidence(), agent_stdout=stream)
    assert runner.execute_plan(plan, execute=fake, events="events.ndjson", log=lambda _: None) == runner.EXIT_OK
    events = [json.loads(line) for line in (plan.run_dir / "events.ndjson").read_text().splitlines()]
    kinds = [e["type"] for e in events]
    assert "agent.message" in kinds and "agent.tool" in kinds
    assert "probing the API now" in [e.get("text") for e in events]
    assert secret not in (plan.run_dir / "events.ndjson").read_text(), "no secret may reach the events file"
    for event in events:
        assert check(event) == [], event


def test_on_ask_fail_aborts_through_teardown(make_recipe, repo, tmp_path):
    plan = _plan(make_recipe(), repo, tmp_path)
    executed = []

    def fake_exec(argv, timeout):
        executed.append(argv)
        if " ".join(argv).startswith("sbx policy log"):
            return subprocess.CompletedProcess(argv, 0, "{}", "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    def fake_stream(argv, timeout, on_line, abort):
        # The "agent" asks, then streams until the bridge aborts it.
        ask_dir = plan.workspace / ".lab" / "ask"
        ask_dir.mkdir(parents=True, exist_ok=True)
        (ask_dir / "a9.json").write_text(
            json.dumps({"ask_id": "a9", "question": "delete everything?", "choices": [], "allow_text": True, "timeout_s": 60}),
            encoding="utf-8",
        )
        deadline = time.monotonic() + 10
        while not abort() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert abort(), "the bridge never signalled abort"
        return subprocess.CompletedProcess(argv, -15, "", "")

    code = runner.execute_plan(plan, execute=fake_exec, stream_exec=fake_stream, on_ask="fail", log=lambda _: None)
    assert code == runner.EXIT_RUN_FAILED
    meta = json.loads((plan.run_dir / "report.json").read_text())["run"]
    assert meta["status"].startswith("aborted")
    assert meta["asks"][0]["state"] == "unanswered"
    assert any(c[1:2] == ["rm"] for c in executed), "teardown (sbx rm) must still run"


def test_kits_grant_passwordless_sudo():
    kits = ROOT / "kits"
    for name in ("base-kali", "base-ubuntu", "base-remnux"):
        text = (kits / name / f"{name}.dockerfile").read_text()
        assert "NOPASSWD:ALL" in text, name
        assert "/etc/sudoers.d/agent" in text and "0440" in text, name
    sbx_src = (ROOT / "lab" / "sbx.py").read_text()
    assert "TODO(verify)" in sbx_src and "Debian" in sbx_src, "built-in Debian sudo path must be marked"


def test_lab_ask_shipped_and_executable(make_recipe, repo, tmp_path):
    plan = _plan(make_recipe(), repo, tmp_path)
    runner.prepare_workspace(plan, repo_root=repo)
    shipped = plan.workspace / ".lab" / "bin" / "lab-ask"
    assert shipped.is_file() and os.access(shipped, os.X_OK)
    agent = next(s for s in plan.all_steps() if s.name == "agent")
    env = " ".join(agent.argv)
    assert "LAB_WORKSPACE" in env and "PATH=" not in env.replace("LAB_TARGET_PATH=", "")
    task = (plan.workspace / "TASK.md").read_text()
    assert "## Asking the operator" in task and f"{plan.workspace}/.lab/bin/lab-ask" in task
    skill = (ROOT / "skills" / "evidence-hygiene" / "SKILL.md").read_text()
    assert "lab-ask" in skill


def test_parse_on_ask():
    assert runner.parse_on_ask(None, False) == {"mode": "timeout", "seconds": 1800}
    assert runner.parse_on_ask(None, True) == {"mode": "skip"}
    assert runner.parse_on_ask("timeout=90s", False)["seconds"] == 90
    assert runner.parse_on_ask("timeout=30m", False)["seconds"] == 1800
    assert runner.parse_on_ask("skip", False) == {"mode": "skip"}
    with pytest.raises(runner.Refused):
        runner.parse_on_ask("banana", False)
