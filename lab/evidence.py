"""Evidence loading, the "no proof, no finding" gate and redaction."""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import cvss, jsonschema_lite

SCHEMA_PATH = Path(__file__).parent / "schema" / "evidence.schema.json"
EVIDENCE_FILE = "evidence.json"

# Patterns for secrets that must never reach a report. Each keeps a short
# prefix so a reader can still tell which credential was found.
_REDACTIONS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("bearer", re.compile(r"(?i)\b(authorization:\s*bearer\s+)[A-Za-z0-9._~+/=-]{16,}")),
    ("password-assignment", re.compile(r"(?i)\b((?:password|passwd|secret|api[_-]?key|token)\s*[=:]\s*)(['\"]?)[^\s'\"]{8,}\2")),
)


def redact(
    text: str,
    extra_values: list[str] | tuple[str, ...] = (),
    seeds: Seeds | None = None,
    agent: bool = False,
) -> tuple[str, int]:
    """Mask secrets in ``text``. Returns the new text and the number of hits.

    ``extra_values`` are literal strings (for example --app-env values) that
    are masked wherever they appear. ``seeds`` are secret values seen in the
    target or the tool artifacts during this run: each is masked, and so is
    any fragment of one (6+ characters with a digit and a letter), so a
    partial value in a command line never reaches a terminal.
    """
    count = 0
    for value in extra_values:
        if value and value in text:
            count += text.count(value)
            text = text.replace(value, "[REDACTED:app-env]")
    if seeds is not None:
        text, n = seeds.mask(text, agent=agent)
        count += n
    for label, pattern in _REDACTIONS:

        def _sub(match: re.Match[str], label: str = label) -> str:
            nonlocal count
            count += 1
            if label in ("bearer", "password-assignment"):
                return f"{match.group(1)}[REDACTED:{label}]"
            return f"{match.group(0)[:4]}[REDACTED:{label}]"

        text = pattern.sub(_sub, text)
    return text, count


def redact_obj(
    obj: Any,
    extra_values: list[str] | tuple[str, ...] = (),
    seeds: Seeds | None = None,
    agent: bool = False,
) -> tuple[Any, int]:
    """Recursively redact every string in a JSON-like object."""
    total = 0

    def walk(value: Any) -> Any:
        nonlocal total
        if isinstance(value, str):
            new, n = redact(value, extra_values, seeds, agent)
            total += n
            return new
        if isinstance(value, list):
            return [walk(v) for v in value]
        if isinstance(value, dict):
            return {k: walk(v) for k, v in value.items()}
        return value

    return walk(obj), total


# Values worth remembering as secrets: assignments to key-like names, AWS
# secret keys, and every _REDACTIONS match.
_SEED_PATTERNS = (
    re.compile(r"(?i)(?:key|token|secret|passw(?:or)?d|pwd|credential|auth)[A-Za-z0-9_]*[\"']?\s*[=:]\s*[\"']?([A-Za-z0-9/+_.=-]{12,256})"),
    re.compile(r"(?<![A-Za-z0-9/+])([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])"),
)
# Scanner fields that hold a raw secret (gitleaks Secret, trufflehog Raw).
_SCANNER_KEYS = {"Secret", "Raw"}
_TOKEN_RE = re.compile(r"[A-Za-z0-9/+_=.-]{6,}")
_TOKEN_FULL = re.compile(r"[A-Za-z0-9/+_=.-]+")
_IDS = re.compile(r"(?i)^(?:CVE|GHSA|GO|PYSEC|RUSTSEC|OSV)-")
GRAM = 6
MAX_HOST_SEEDS, MAX_AGENT_SEEDS, MAX_SEED_LEN = 2000, 200, 128


def _seedworthy(value: str) -> bool:
    if not 8 <= len(value) <= MAX_SEED_LEN or not _TOKEN_FULL.fullmatch(value):
        return False
    if "REDACTED" in value or len(set(value)) < 5 or _IDS.match(value):
        return False
    return any(c.isdigit() for c in value) and any(c.isalpha() for c in value)


class _SeedSet:
    """Seeds indexed by 6-grams, so masking stays linear in the text."""

    def __init__(self, cap: int) -> None:
        self.cap = cap
        self.values: set[str] = set()
        self.by_gram: dict[str, list[str]] = {}  # any 6-gram -> seeds containing it
        self.by_prefix: dict[str, list[str]] = {}  # leading 6-gram -> seeds

    def add(self, value: str) -> None:
        if value in self.values or len(self.values) >= self.cap:
            return
        self.values.add(value)
        self.by_prefix.setdefault(value[:GRAM], []).append(value)
        for i in range(len(value) - GRAM + 1):
            bucket = self.by_gram.setdefault(value[i : i + GRAM], [])
            if not bucket or bucket[-1] != value:
                bucket.append(value)

    def hits(self, token: str) -> bool:
        """True when token holds a seed or is a 6+ char piece of one."""
        if not self.values:
            return False
        core = token.strip("./=-_")
        if len(core) >= GRAM and any(c.isdigit() for c in core) and any(c.isalpha() for c in core):
            for seed in self.by_gram.get(core[:GRAM], ()):
                if core in seed:
                    return True
        for i in range(len(token) - GRAM + 1):
            for seed in self.by_prefix.get(token[i : i + GRAM], ()):
                if token.startswith(seed, i):
                    return True
        return False


class Seeds:
    """Secret values seen during a run.

    Host seeds come from the host copy of the target and its git history
    and mask everything. Agent seeds come from the agent-writable evidence
    folder: they only mask agent-authored text (``mask(..., agent=True)``),
    so a hostile agent cannot erase runner records such as the policy log.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.host = _SeedSet(MAX_HOST_SEEDS)
        self.agent = _SeedSet(MAX_AGENT_SEEDS)

    @property
    def values(self) -> set[str]:
        return self.host.values | self.agent.values

    def add(self, value: Any, agent: bool = False) -> None:
        if not isinstance(value, str):
            return
        value = value.strip().strip("\"'")
        if not _seedworthy(value):
            return
        with self._lock:
            (self.agent if agent else self.host).add(value)

    def harvest(self, text: str) -> None:
        """Host text: assignments, AWS secret shapes, _REDACTIONS matches."""
        for pattern in _SEED_PATTERNS:
            for match in pattern.finditer(text):
                self.add(match.group(1))
        self._harvest_patterns(text, agent=False)

    def _harvest_patterns(self, text: str, agent: bool) -> None:
        for _, pattern in _REDACTIONS:
            for match in pattern.finditer(text):
                if match.lastindex is None:
                    self.add(match.group(0), agent=agent)

    def scan_tree(self, root: Path, max_files: int = 5000, max_file: int = 1 << 20, budget: int = 64 << 20) -> None:
        """Harvest a host folder (no symlinks, no .git) within caps."""
        if root.is_file() and not root.is_symlink():
            self._scan_file(root, max_file)
            return
        seen = 0
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d != ".git"]
            for name in filenames:
                path = Path(dirpath) / name
                seen += 1
                if seen > max_files or budget <= 0:
                    return
                budget -= self._scan_file(path, max_file)

    def _scan_file(self, path: Path, max_file: int) -> int:
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > max_file:
                return 0
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return 0
        self.harvest(text)
        return len(text)

    def scan_git(self, root: Path, git_opts: tuple[str, ...] = (), max_bytes: int = 32 << 20, timeout: int = 60) -> None:
        """Harvest the history of a host clone (deleted files keep secrets)."""
        if not (root / ".git").exists():
            return
        argv = ["git", *git_opts, "-C", str(root), "log", "-p", "--all", "--no-color", "--no-ext-diff", "--no-textconv"]
        try:
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        except OSError:
            return
        assert proc.stdout is not None
        deadline = time.monotonic() + timeout
        read = 0
        chunk = b""
        try:
            while read < max_bytes and time.monotonic() < deadline:
                data = proc.stdout.read(1 << 16)
                if not data:
                    break
                read += len(data)
                chunk += data
                cut = chunk.rfind(b"\n")
                if cut >= 0:
                    self.harvest(chunk[:cut].decode("utf-8", "replace"))
                    chunk = chunk[cut + 1 :]
            self.harvest(chunk.decode("utf-8", "replace"))
        finally:
            proc.kill()
            proc.wait()

    def scan_artifacts(self, root: Path, max_file: int = 8 << 20) -> None:
        """Agent seeds from saved tool output: only _REDACTIONS matches and
        known scanner fields (gitleaks Secret, trufflehog Raw)."""
        if not root.is_dir() or root.is_symlink():
            return
        for path in sorted(root.rglob("*"))[:2000]:
            try:
                if path.is_symlink() or not path.is_file() or path.stat().st_size > max_file:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            self._harvest_patterns(text, agent=True)
            for line in text.splitlines() if path.suffix == ".jsonl" else [text]:
                try:
                    self._walk_json(json.loads(line))
                except (json.JSONDecodeError, RecursionError):
                    continue

    def _walk_json(self, obj: Any) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, str) and key in _SCANNER_KEYS:
                    self.add(value, agent=True)
                else:
                    self._walk_json(value)
        elif isinstance(obj, list):
            for value in obj[:10000]:
                self._walk_json(value)

    def mask(self, text: str, agent: bool = False) -> tuple[str, int]:
        """Mask every token that holds a seed or a 6+ char piece of one.
        ``agent=True`` also applies agent seeds (agent-authored text only)."""
        sets = [self.host, self.agent] if agent else [self.host]
        if not any(s.values for s in sets):
            return text, 0
        count = 0

        def _sub(match: re.Match[str]) -> str:
            nonlocal count
            token = match.group(0)
            with self._lock:
                hit = any(s.hits(token) for s in sets)
            if hit:
                count += 1
                return "[REDACTED:seen-secret]"
            return token

        return _TOKEN_RE.sub(_sub, text), count


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class GateResult:
    evidence: dict[str, Any]
    schema_errors: list[str] = field(default_factory=list)
    demoted: list[dict[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    redactions: int = 0

    @property
    def ok(self) -> bool:
        return not self.schema_errors


def empty(recipe_id: str, summary: str) -> dict[str, Any]:
    return {
        "schema_version": "1",
        "recipe": recipe_id,
        "summary": summary,
        "tools_run": [],
        "findings": [],
        "hypotheses": [],
        "artifacts": [],
    }


def load(evidence_dir: Path) -> dict[str, Any]:
    path = evidence_dir / EVIDENCE_FILE
    if not path.is_file():
        raise FileNotFoundError(f"no {EVIDENCE_FILE} in {evidence_dir}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: evidence must be a JSON object")
    return data


def _inside(base: Path, rel: str) -> Path | None:
    """Resolve ``rel`` under ``base``; None when it escapes or is absolute."""
    if not rel or rel.startswith(("/", "~")):
        return None
    candidate = (base / rel).resolve()
    try:
        candidate.relative_to(base.resolve())
    except ValueError:
        return None
    return candidate


def _proof_problem(finding: dict[str, Any], evidence_dir: Path) -> str | None:
    proof = finding.get("proof") or {}
    if not str(proof.get("poc") or "").strip():
        return "no PoC"
    artifacts = proof.get("artifacts") or []
    if not artifacts:
        return "no artifact"
    for rel in artifacts:
        path = _inside(evidence_dir, rel)
        if path is None:
            return f"artifact path escapes evidence/: {rel}"
        if not path.is_file():
            return f"artifact missing: {rel}"
        if path.stat().st_size == 0:
            return f"artifact is empty: {rel}"
    return None


def gate(
    data: dict[str, Any],
    evidence_dir: Path,
    scope: Any = None,
    extra_values: list[str] | tuple[str, ...] = (),
    seeds: Seeds | None = None,
) -> GateResult:
    """Apply the evidence gate.

    - validate against the evidence schema
    - demote findings without a PoC and existing artifacts to ``hypotheses``
    - demote findings whose target is outside the scope
    - check CVSS vectors against their scores and align the severity
    - hash artifacts and redact secrets from every text field
    """
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    result = GateResult(evidence=copy.deepcopy(data))
    result.schema_errors = jsonschema_lite.validate(data, schema)
    if result.schema_errors:
        return result

    ev = result.evidence
    kept: list[dict[str, Any]] = []
    for finding in ev["findings"]:
        problem = _proof_problem(finding, evidence_dir)
        if problem is None and scope is not None and scope.target_hosts:
            host = _host_of(finding["target"])
            if host and not scope.in_scope(host):
                problem = f"target {host} is out of scope"
        if problem is None and "cvss" in finding:
            try:
                expected = cvss.base_score(finding["cvss"]["vector"])
            except cvss.CVSSError as exc:
                problem = f"invalid CVSS vector: {exc}"
            else:
                if abs(expected - float(finding["cvss"]["score"])) > 0.05:
                    result.warnings.append(f"{finding['id']}: CVSS score {finding['cvss']['score']} corrected to {expected} (from vector)")
                    finding["cvss"]["score"] = expected
                sev = cvss.severity(expected)
                if sev != finding["severity"]:
                    result.warnings.append(f"{finding['id']}: severity {finding['severity']} corrected to {sev} (from CVSS)")
                    finding["severity"] = sev
        if problem is None:
            kept.append(finding)
            continue
        result.demoted.append({"id": finding["id"], "reason": problem})
        ev["hypotheses"].append(
            {
                "id": f"H-{finding['id']}",
                "title": finding["title"],
                "rationale": finding["description"],
                "next_step": "Produce a PoC and attach the artifacts that prove it.",
                "demoted_from": finding["id"],
                "demoted_reason": problem,
            }
        )
    ev["findings"] = kept

    for artifact in ev["artifacts"]:
        path = _inside(evidence_dir, artifact["path"])
        if path is None or not path.is_file():
            result.warnings.append(f"artifact listed but not found: {artifact['path']}")
            continue
        artifact["sha256"] = sha256_file(path)

    # Evidence is agent-authored: agent seeds apply too.
    result.evidence, result.redactions = redact_obj(ev, extra_values, seeds, agent=True)
    return result


# Last labels that mark a file name rather than a host in a scheme-less target
# (``app.py:20``, ``photo.png``). A few are also real TLDs; such hosts are still
# held by the sandbox network policy, which is the first line of defence.
_FILE_SUFFIXES = frozenset(
    "py js ts go rs c h cc cpp java kt rb php cs swift sh ps1 pl lua "
    "json yaml yml toml ini cfg conf xml html htm md txt csv log lock "
    "png jpg jpeg gif svg pdf bin so dll exe elf zip gz tgz tar pcap pcapng".split()
)
_BARE_HOST_RE = re.compile(r"^(?:[a-z0-9_-]+\.)+([a-z]{2,63})$", re.I)


def _host_of(target: str) -> str | None:
    """Extract ``host[:port]`` from a finding target, if it names a host.

    URL targets give their authority. A scheme-less target is a host when its
    leading ``host[:port]`` token is an IP address, ``localhost`` or a dotted
    host name; file paths and plain labels are not hosts.
    """
    text = target.strip()
    match = re.match(r"^[a-z][a-z0-9+.-]*://([^/\s?#]+)", text, re.I)
    if match:
        return match.group(1).rsplit("@", 1)[-1]
    if not text:
        return None
    token = re.split(r"[\s/?#]", text, maxsplit=1)[0].rsplit("@", 1)[-1]
    host, port = token, None
    v6 = re.match(r"^\[([0-9a-f:.]+)\](?::(\d+))?$", token, re.I)
    if v6:
        host, port = v6.group(1), v6.group(2)
    elif token.count(":") == 1:
        host, port = token.split(":")
        if not port.isdigit():
            return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if host.lower() != "localhost":
            name = _BARE_HOST_RE.match(host)
            if not name or name.group(1).lower() in _FILE_SUFFIXES:
                return None
    if v6:
        return host  # scope.split_host keeps bare IPv6 whole; match on the address
    return f"{host}:{port}" if port else host
