import json
from pathlib import Path

from lab import jsonschema_lite

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / "lab" / "schema" / "events.schema.json").read_text(encoding="utf-8"))
FIXTURE = ROOT / "tests" / "fixtures" / "events" / "run.ndjson"


def _check(event):
    sub = dict(SCHEMA["$defs"][event["type"]])
    sub["$defs"] = SCHEMA["$defs"]
    return jsonschema_lite.validate(event, sub)


def test_schema_lists_every_event_type_once():
    refs = [r["$ref"].rsplit("/", 1)[-1] for r in SCHEMA["oneOf"]]
    assert (
        sorted(refs)
        == sorted(SCHEMA["$defs"])
        == sorted(["step", "agent.message", "agent.tool", "finding", "blocked", "ask", "answer", "done"])
    )


def test_fixture_events_are_valid_and_ordered():
    events = [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").splitlines()]
    assert {e["type"] for e in events} == set(SCHEMA["$defs"]), "the fixture covers every type"
    assert [e["seq"] for e in events] == list(range(len(events)))
    for event in events:
        assert _check(event) == [], event


def test_schema_rejects_bad_events():
    good = {
        "schema_version": "1",
        "type": "ask",
        "seq": 0,
        "ts": "2026-11-21T10:30:00Z",
        "run_id": "r",
        "ask_id": "a1",
        "question": "q?",
        "choices": [],
        "allow_text": True,
        "timeout_s": 30,
    }
    assert _check(good) == []
    for bad in (
        {**good, "ask_id": "../../etc/passwd"},
        {**good, "secret": "x"},
        {k: v for k, v in good.items() if k != "seq"},
        {**good, "ts": "yesterday"},
        {**good, "timeout_s": -1},
    ):
        assert _check(bad), bad
    answer = {
        "schema_version": "1",
        "type": "answer",
        "seq": 1,
        "ts": "2026-11-21T10:30:01Z",
        "run_id": "r",
        "ask_id": "a1",
        "by": "robot",
        "value": "x",
    }
    assert _check(answer), "by must be user, timeout, skip or forged"
    assert _check({**answer, "by": "forged", "value": "yes"}) == []


def test_schema_rejects_escape_sequences_and_oversize_text():
    bad = [json.loads(line) for line in (ROOT / "tests" / "fixtures" / "events" / "reject.ndjson").read_text().splitlines()]
    assert bad and all(_check(event) for event in bad), "an OSC 52 / cursor-move payload must not validate"
    base = {"schema_version": "1", "type": "agent.message", "seq": 0, "ts": "2026-11-21T10:30:00Z", "run_id": "r"}
    assert _check({**base, "text": "line one\n\tline two"}) == [], "tab and newline are allowed"
    assert _check({**base, "text": "caf\u00e9 \u00a0ok"}) == [], "printable non-ASCII stays allowed"
    for text in ("x" * 4097, "bell \u0007", "del \u007f", "cr \r", "c1 csi \u009b", "c1 nel \u0085"):
        assert _check({**base, "text": text}), repr(text)
    ask = {
        "schema_version": "1",
        "type": "ask",
        "seq": 1,
        "ts": "2026-11-21T10:30:01Z",
        "run_id": "r",
        "ask_id": "a1",
        "question": "q?",
        "allow_text": False,
        "timeout_s": 0,
    }
    assert _check({**ask, "choices": ["c"] * 64}) == []
    assert _check({**ask, "choices": ["c"] * 65}), "at most 64 choices"
    assert _check({**ask, "choices": ["x" * 513]}), "at most 512 chars per choice"
