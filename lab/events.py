"""NDJSON event writer for ``lab run --events FILE|-``.

One ``EventWriter`` per run: ``emit(type, **fields)`` adds schema_version,
seq, ts and run_id, sanitizes agent-controlled text, runs the secret
redactions over stream fields and flushes one NDJSON line. Every event is
meant to validate against ``$defs[type]`` in lab/schema/events.schema.json
(the tests check that).
"""

from __future__ import annotations

import datetime as _dt
import json
import sys
import threading
from pathlib import Path
from typing import Any, TextIO

from . import evidence as evidence_mod
from . import sanitize

_SCHEMA_VERSION = "1"

# Per-field limits so emitted events match the schema caps.
_FIELD_LIMITS = {
    "text": sanitize.TEXT_LIMIT,
    "summary": sanitize.TEXT_LIMIT,
    "question": sanitize.TEXT_LIMIT,
    "detail": sanitize.TEXT_LIMIT,
    "title": sanitize.TEXT_LIMIT,
    "value": sanitize.TEXT_LIMIT,
    "tool": 256,
    "report": sanitize.TEXT_LIMIT,
}
# Fields that may carry secrets the agent saw: redact before emit (patterns,
# plus the run's seen secrets and their fragments when seeds are set).
# The operator's own answer (answer.value) is never rewritten.
_REDACT_FIELDS = {"text", "summary", "tool", "question", "detail", "title"}
# Agent-authored event types: seeds harvested from the agent's own files
# apply only here, never to runner records (steps, blocked hosts, done).
_AGENT_TYPES = {"agent.message", "agent.tool", "ask", "finding"}


class EventWriter:
    """Writes one NDJSON event per line to a file or to stdout ("-")."""

    def __init__(self, target: Path | str, run_id: str, stream: TextIO | None = None) -> None:
        self.run_id = run_id
        self.seq = 0
        self.seeds: evidence_mod.Seeds | None = None
        self._lock = threading.Lock()
        self._own = stream is None and str(target) != "-"
        if stream is not None:
            self._fh = stream
        elif str(target) == "-":
            self._fh = sys.stdout
        else:
            path = Path(target)
            path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = path.open("w", encoding="utf-8")

    def emit(self, type_: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            event = {
                "schema_version": _SCHEMA_VERSION,
                "type": type_,
                "seq": self.seq,
                "ts": _dt.datetime.now(_dt.UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "run_id": self.run_id,
            }
            agent = type_ in _AGENT_TYPES
            for key, value in fields.items():
                if key == "choices" and isinstance(value, list):
                    value = [evidence_mod.redact(str(c), seeds=self.seeds, agent=agent)[0] for c in value]
                    event[key] = sanitize.clean_choices(value)
                elif isinstance(value, str):
                    if key in _REDACT_FIELDS:
                        value, _ = evidence_mod.redact(value, seeds=self.seeds, agent=agent)
                    event[key] = sanitize.clean_text(value, _FIELD_LIMITS.get(key, sanitize.TEXT_LIMIT))
                else:
                    event[key] = value
            self.seq += 1
            self._fh.write(json.dumps(event, ensure_ascii=False) + "\n")
            self._fh.flush()
        return event

    def close(self) -> None:
        if self._own:
            self._fh.close()


class NullWriter(EventWriter):
    """Same API, writes nothing. Used when no --events target is given."""

    def __init__(self, run_id: str) -> None:
        super().__init__("-", run_id, stream=_DevNull())

    def close(self) -> None:
        pass


class _DevNull:
    def write(self, _: str) -> int:
        return 0

    def flush(self) -> None:
        pass
