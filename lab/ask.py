"""Host side of the ask bridge (agent -> operator -> agent).

Inside the sandbox ``lab-ask`` writes ``.lab/ask/<id>.json`` into the shared
workspace and waits for ``.lab/ask/<id>.answer.json``. ``AskBridge`` runs on
the host while the agent step runs: it watches the directory, emits ``ask``
events, resolves an answer from the configured channel and writes the
answer file itself — the host is the only authority on answers.

Channels for answers: ``runs/<id>/control.sock`` (a unix socket burner
writes to, always created), ``--answers DIR`` (a file named ``<ask_id>``
holding the value) or ``--answers FIFO`` (one JSON line per answer).
Every ask and every answer the bridge delivered is recorded in
``runs/<id>/asks.jsonl`` — outside the workspace, so the agent cannot
rewrite it. An answer file the bridge did not write is reported as forged,
never counted as delivered.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import socket
import stat
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

ASK_DIR = ".lab/ask"
ASK_LOG = "asks.jsonl"
CONTROL_SOCK = "control.sock"
POLL_S = 0.25
VALUE_LIMIT = 4096
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class AskError(ValueError):
    """The ask bridge cannot start (control socket, answer channel)."""


def _now() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class AskBridge:
    """Watches ``<workspace>/.lab/ask`` and delivers operator answers.

    ``emit`` is ``EventWriter.emit`` (or a stub). ``on_ask`` is
    ``{"mode": "timeout", "seconds": N}``, ``{"mode": "skip"}`` or
    ``{"mode": "fail"}``. ``answers`` is a directory or FIFO path.
    """

    def __init__(
        self,
        workspace: Path | str,
        run_dir: Path | str,
        *,
        on_ask: dict[str, Any] | None = None,
        answers: Path | str | None = None,
        emit: Callable[..., dict[str, Any]] | None = None,
        log: Callable[[str], None] | None = None,
    ) -> None:
        self.workspace = Path(workspace)
        self.ask_dir = self.workspace / ASK_DIR
        self.run_dir = Path(run_dir)
        self.on_ask = on_ask or {"mode": "timeout", "seconds": 1800}
        self.answers_path = Path(answers) if answers else None
        self.emit = emit or (lambda *a, **k: {})
        self.log = log or (lambda _: None)
        self.pending: dict[str, dict[str, Any]] = {}
        self.records: list[dict[str, Any]] = []
        self.forged: list[str] = []
        self.abort = False
        # ask_id -> (sha256, inode) of every answer file the bridge wrote.
        self._written: dict[str, tuple[str, int]] = {}
        self._seen_forged: set[str] = set()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._sock: socket.socket | None = None
        self._lock = threading.Lock()
        self._dlock = threading.Lock()

    # -- lifecycle -------------------------------------------------------

    def start(self) -> None:
        self.ask_dir.mkdir(parents=True, exist_ok=True)
        self._open_control_socket()
        if self.answers_path is not None:
            self._check_answers_path()
        self._spawn(self._watch_loop)
        self._spawn(self._sock_loop)
        if self.answers_path is not None:
            if self.answers_path.is_dir():
                self._spawn(self._dir_loop)
            else:
                self._spawn(self._fifo_loop)

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        for thread in self._threads:
            thread.join(timeout=2)
        self._scan_forged()

    # -- channels --------------------------------------------------------

    def _open_control_socket(self) -> None:
        path = self.run_dir / CONTROL_SOCK
        if path.is_symlink() or (path.exists() and not stat.S_ISSOCK(path.stat().st_mode)):
            raise AskError(f"refusing control socket: {path} exists and is not a socket")
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            # Bind a relative path through fchdir: sun_path is ~104 bytes, far
            # shorter than a deep runs-dir path. Runs before any thread starts.
            old_cwd = os.open(".", os.O_RDONLY)
            run_fd = os.open(self.run_dir, os.O_RDONLY)
            try:
                os.fchdir(run_fd)
                self._sock.bind(CONTROL_SOCK)
            finally:
                os.fchdir(old_cwd)
                os.close(run_fd)
                os.close(old_cwd)
            os.chmod(path, 0o600)
        except OSError as exc:
            raise AskError(f"cannot create control socket {path}: {exc}") from exc
        self._sock.listen(8)
        self._sock.settimeout(0.5)

    def _check_answers_path(self) -> None:
        path = self.answers_path
        assert path is not None
        if path.is_dir() or stat.S_ISFIFO(path.stat().st_mode if path.exists() else 0):
            return
        raise AskError(f"--answers {path} is neither a directory nor a FIFO")

    # -- the watch loop ----------------------------------------------------

    def _spawn(self, fn: Callable[[], None]) -> None:
        thread = threading.Thread(target=fn, daemon=True)
        thread.start()
        self._threads.append(thread)

    def _watch_loop(self) -> None:
        while not self._stop.is_set():
            self._scan_questions()
            self._scan_forged()
            self._expire()
            self._stop.wait(POLL_S)

    def _scan_questions(self) -> None:
        try:
            files = sorted(self.ask_dir.glob("*.json"))
        except OSError:
            return
        for path in files:
            if path.name.endswith(".answer.json"):
                continue
            ask_id = path.name[: -len(".json")]
            if not _ID_RE.match(ask_id) or ask_id in self.pending:
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if data.get("ask_id") != ask_id:
                continue
            record = {
                "ask_id": ask_id,
                "question": str(data.get("question", "")),
                "choices": data.get("choices") if isinstance(data.get("choices"), list) else [],
                "allow_text": bool(data.get("allow_text")),
                "timeout_s": int(data.get("timeout_s") or 0),
                "state": "asked",
                "answers": [],
            }
            self.pending[ask_id] = record
            self.records.append(record)
            self.emit(
                "ask",
                ask_id=ask_id,
                question=record["question"],
                choices=record["choices"],
                allow_text=record["allow_text"],
                timeout_s=record["timeout_s"],
            )
            self._log({"ts": _now(), "event": "ask", "ask_id": ask_id})
            if self.on_ask["mode"] == "skip":
                self._deliver(ask_id, None, "skip")
            elif self.on_ask["mode"] == "fail":
                record["state"] = "unanswered"
                self.abort = True

    def _flag_forged(self, name: str, ask_id: str, tampered: bool) -> None:
        if name in self._seen_forged:
            return
        self._seen_forged.add(name)
        # Publish last: readers of `forged` must find the event and the log
        # line already written (it was appended first, which raced readers).
        self.emit("answer", ask_id=ask_id, by="forged", value=None)
        self._log({"ts": _now(), "event": "forged", "ask_id": ask_id, "file": name, "tampered": tampered})
        self.forged.append(name)

    def _scan_forged(self) -> None:
        try:
            files = sorted(self.ask_dir.glob("*.answer.json"))
        except OSError:
            return
        for path in files:
            ask_id = path.name[: -len(".answer.json")]
            known = self._written.get(ask_id)
            if known is None:
                self._flag_forged(path.name, ask_id, tampered=False)
                continue
            digest, ino = known
            try:
                current = hashlib.sha256(path.read_bytes()).hexdigest()
                tampered = current != digest or path.stat().st_ino != ino
            except OSError:
                tampered = True
            if tampered:
                self._flag_forged(path.name, ask_id, tampered=True)
        for ask_id in self._written:
            name = f"{ask_id}.answer.json"
            if not (self.ask_dir / name).exists():
                self._flag_forged(name, ask_id, tampered=True)

    def _expire(self) -> None:
        if self.on_ask["mode"] != "timeout":
            return
        now = time.monotonic()
        for ask_id, record in list(self.pending.items()):
            if record["state"] != "asked":
                continue
            asked_at = record.setdefault("_asked_at", now)
            deadline = float(self.on_ask["seconds"])
            if record["timeout_s"] > 0:
                deadline = min(deadline, float(record["timeout_s"]))
            if now - asked_at >= deadline:
                self._deliver(ask_id, None, "timeout")

    # -- answering ---------------------------------------------------------

    def _deliver(self, ask_id: str, value: Any, by: str) -> bool:
        record = self.pending.get(ask_id)
        if record is None or record["state"] != "asked":
            return False
        if isinstance(value, str) and len(value) > VALUE_LIMIT:
            return False
        with self._dlock:
            if record["state"] != "asked":
                return False
            record["state"] = by
            record["answers"].append({"by": by, "value": value, "ts": _now()})
        answer = self.ask_dir / f"{ask_id}.answer.json"
        tmp = self.ask_dir / f".{ask_id}.answer.json.tmp"
        payload = json.dumps({"ask_id": ask_id, "value": value}) + "\n"
        tmp.write_text(payload, encoding="utf-8")
        tmp.replace(answer)
        try:
            self._written[ask_id] = (hashlib.sha256(payload.encode()).hexdigest(), answer.stat().st_ino)
        except OSError:
            self._written[ask_id] = (hashlib.sha256(payload.encode()).hexdigest(), -1)
        self.emit("answer", ask_id=ask_id, by=by, value=value)
        self._log({"ts": _now(), "event": "answer", "ask_id": ask_id, "by": by, "value": value})
        return True

    def deliver(self, ask_id: str, value: Any) -> bool:
        """Deliver an operator answer; False when the id is unknown or done."""
        return self._deliver(ask_id, value, "user")

    def _log(self, entry: dict[str, Any]) -> None:
        with self._lock:
            with (self.run_dir / ASK_LOG).open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    # -- channel loops -------------------------------------------------------

    def _sock_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with conn:
                reply = self._handle_socket_line(conn)
                try:
                    conn.sendall((json.dumps(reply) + "\n").encode())
                except OSError:  # client went away; the answer is recorded anyway
                    pass

    def _handle_socket_line(self, conn: socket.socket) -> dict[str, Any]:
        try:
            conn.settimeout(5)
            data = b""
            while b"\n" not in data and len(data) <= 8192:
                chunk = conn.recv(8192)
                if not chunk:
                    break
                data += chunk
            line = json.loads(data.decode().splitlines()[0])
            ask_id, value = str(line["ask_id"]), line.get("value")
        except (IndexError, KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
            return {"error": 'expected one JSON line {"ask_id": ..., "value": ...}'}
        if not _ID_RE.match(ask_id):
            return {"error": "bad ask_id"}
        if not isinstance(value, (str, type(None))):
            return {"error": "value must be a string"}
        if isinstance(value, str) and len(value) > VALUE_LIMIT:
            return {"error": f"value over {VALUE_LIMIT} chars"}
        if not self._deliver(ask_id, value, "user"):
            return {"error": "unknown or already-answered ask_id"}
        return {"ok": True}

    def _dir_loop(self) -> None:
        assert self.answers_path is not None
        while not self._stop.is_set():
            try:
                files = sorted(self.answers_path.iterdir())
            except OSError:
                files = []
            for path in files:
                ask_id = path.name
                if ask_id not in self.pending or not _ID_RE.match(ask_id):
                    continue
                try:
                    value = path.read_text(encoding="utf-8").strip()
                except OSError:
                    continue
                if self._deliver(ask_id, value, "user"):
                    try:
                        path.unlink()
                    except OSError:
                        pass
            self._stop.wait(POLL_S)

    def _fifo_loop(self) -> None:
        assert self.answers_path is not None
        try:
            fd = os.open(self.answers_path, os.O_RDWR | os.O_NONBLOCK)
        except OSError as exc:
            self.log(f"    ask bridge: cannot open {self.answers_path}: {exc}")
            return
        buf = b""
        try:
            while not self._stop.is_set():
                try:
                    chunk = os.read(fd, 8192)
                except BlockingIOError:
                    chunk = b""
                if chunk:
                    buf += chunk
                    while b"\n" in buf:
                        raw, buf = buf.split(b"\n", 1)
                        self._handle_fifo_line(raw)
                else:
                    self._stop.wait(POLL_S)
        finally:
            os.close(fd)

    def _handle_fifo_line(self, raw: bytes) -> None:
        try:
            line = json.loads(raw.decode())
            ask_id, value = str(line["ask_id"]), line.get("value")
        except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
            return
        if _ID_RE.match(ask_id) and isinstance(value, (str, type(None))):
            self._deliver(ask_id, value, "user")

    # -- report ------------------------------------------------------------

    def report_asks(self) -> list[dict[str, Any]]:
        """The ``run.asks`` records for report.json (host log is the truth)."""
        out = []
        for record in self.records:
            out.append(
                {
                    "ask_id": record["ask_id"],
                    "question": record["question"],
                    "choices": record["choices"],
                    "allow_text": record["allow_text"],
                    "timeout_s": record["timeout_s"],
                    "state": record["state"],
                    "answers": record["answers"],
                }
            )
        return out
