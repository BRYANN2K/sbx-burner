"""A small YAML subset parser (stdlib only).

The lab runner must not depend on third-party packages, so recipe, scope and
index files are restricted to this subset:

- block mappings and block sequences (including ``- key: value`` items)
- flow sequences ``[a, b]`` and flow mappings ``{a: b}`` on one line
- scalars: plain, single-quoted, double-quoted, int, float, bool, null
- literal ``|`` and folded ``>`` block scalars (with optional ``-`` chomping)
- ``#`` comments

Not supported: anchors/aliases, tags, multi-document streams, complex keys,
multi-line flow collections. ``python -m lab lint`` rejects files outside the
subset, so every recipe stays parseable by the runner.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["YAMLError", "loads", "load", "split_frontmatter"]


class YAMLError(ValueError):
    """Raised when a document is outside the supported subset."""


_INT = re.compile(r"^[-+]?\d+$")
_FLOAT = re.compile(r"^[-+]?(\d+\.\d*|\.\d+|\d+)([eE][-+]?\d+)?$")
_KEY = re.compile(
    r"""^(?P<key>"(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s#:'"\[\]{},&*!|>%@`-][^:#]*?|-[^\s:#][^:#]*?)\s*:(?:\s+(?P<rest>.*))?$"""
)


def _strip_comment(line: str) -> str:
    """Remove a trailing ``#`` comment, respecting quotes."""
    quote = ""
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip()
    return line.rstrip()


def _split_flow(body: str) -> list[str]:
    parts, depth, quote, cur = [], 0, "", []
    for ch in body:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "'\"":
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)
    return parts


def _scalar(text: str) -> Any:
    text = text.strip()
    if text == "" or text in ("~", "null", "Null", "NULL"):
        return None
    if text[0] == '"':
        if len(text) < 2 or text[-1] != '"':
            raise YAMLError(f"unterminated double-quoted scalar: {text!r}")
        body = text[1:-1]
        return re.sub(
            r"\\(.)",
            lambda m: {"n": "\n", "t": "\t", "0": "\0"}.get(m.group(1), m.group(1)),
            body,
        )
    if text[0] == "'":
        if len(text) < 2 or text[-1] != "'":
            raise YAMLError(f"unterminated single-quoted scalar: {text!r}")
        return text[1:-1].replace("''", "'")
    if text[0] == "[":
        if text[-1] != "]":
            raise YAMLError(f"multi-line flow sequences are not supported: {text!r}")
        return [_scalar(p) for p in _split_flow(text[1:-1])]
    if text[0] == "{":
        if text[-1] != "}":
            raise YAMLError(f"multi-line flow mappings are not supported: {text!r}")
        out: dict[str, Any] = {}
        for part in _split_flow(text[1:-1]):
            if ":" not in part:
                raise YAMLError(f"bad flow mapping entry: {part!r}")
            k, v = part.split(":", 1)
            out[str(_scalar(k))] = _scalar(v)
        return out
    if text[0] in "&*!":
        raise YAMLError(f"anchors, aliases and tags are not supported: {text!r}")
    if text in ("true", "True", "TRUE"):
        return True
    if text in ("false", "False", "FALSE"):
        return False
    if _INT.match(text):
        return int(text)
    if _FLOAT.match(text) and any(c in text for c in ".eE"):
        return float(text)
    return text


class _Parser:
    def __init__(self, text: str) -> None:
        self.raw = text.splitlines()
        # (indent, content, raw_index) for every structural line
        self.lines: list[tuple[int, str, int]] = []
        for idx, raw in enumerate(self.raw):
            if "\t" in raw[: len(raw) - len(raw.lstrip())]:
                raise YAMLError(f"line {idx + 1}: tabs are not allowed for indentation")
            content = _strip_comment(raw)
            if not content.strip():
                continue
            if content.strip() in ("---", "..."):
                if self.lines:
                    raise YAMLError("multi-document streams are not supported")
                continue
            self.lines.append((len(content) - len(content.lstrip()), content.strip(), idx))
        self.pos = 0

    def parse(self) -> Any:
        if not self.lines:
            return None
        value = self._block(self.lines[0][0])
        if self.pos < len(self.lines):
            raise YAMLError(f"line {self.lines[self.pos][2] + 1}: unexpected indentation")
        return value

    def _block(self, indent: int) -> Any:
        _, content, _ = self.lines[self.pos]
        if content == "-" or content.startswith("- "):
            return self._sequence(indent)
        if _KEY.match(content):
            return self._mapping(indent)
        self.pos += 1
        return _scalar(content)

    def _sequence(self, indent: int) -> list[Any]:
        out: list[Any] = []
        while self.pos < len(self.lines):
            ind, content, raw_idx = self.lines[self.pos]
            if ind != indent or not (content == "-" or content.startswith("- ")):
                if ind > indent:
                    raise YAMLError(f"line {raw_idx + 1}: bad indentation in sequence")
                break
            rest = content[1:].strip()
            if not rest:
                self.pos += 1
                if self.pos < len(self.lines) and self.lines[self.pos][0] > indent:
                    out.append(self._block(self.lines[self.pos][0]))
                else:
                    out.append(None)
            elif _KEY.match(rest) and rest[0] not in "[{":
                # "- key: value": re-enter as a mapping indented past the dash
                inner = indent + (len(content) - len(rest))
                self.lines[self.pos] = (inner, rest, raw_idx)
                out.append(self._mapping(inner))
            else:
                self.pos += 1
                out.append(self._value(rest, indent, raw_idx))
        return out

    def _mapping(self, indent: int) -> dict[str, Any]:
        out: dict[str, Any] = {}
        while self.pos < len(self.lines):
            ind, content, raw_idx = self.lines[self.pos]
            if ind != indent:
                if ind > indent:
                    raise YAMLError(f"line {raw_idx + 1}: bad indentation in mapping")
                break
            m = _KEY.match(content)
            if not m:
                raise YAMLError(f"line {raw_idx + 1}: expected 'key: value', got {content!r}")
            key = str(_scalar(m.group("key")))
            if key in out:
                raise YAMLError(f"line {raw_idx + 1}: duplicate key {key!r}")
            rest = (m.group("rest") or "").strip()
            self.pos += 1
            if rest:
                out[key] = self._value(rest, indent, raw_idx)
            elif self.pos < len(self.lines) and (
                self.lines[self.pos][0] > indent
                or (self.lines[self.pos][0] == indent and (self.lines[self.pos][1] == "-" or self.lines[self.pos][1].startswith("- ")))
            ):
                out[key] = self._block(self.lines[self.pos][0])
            else:
                out[key] = None
        return out

    def _value(self, rest: str, indent: int, raw_idx: int) -> Any:
        if re.fullmatch(r"[|>][-+]?", rest):
            return self._block_scalar(rest, indent, raw_idx)
        return _scalar(rest)

    def _block_scalar(self, style: str, indent: int, raw_idx: int) -> str:
        body: list[str] = []
        i = raw_idx + 1
        block_indent = None
        while i < len(self.raw):
            raw = self.raw[i]
            if raw.strip():
                ind = len(raw) - len(raw.lstrip())
                if ind <= indent:
                    break
                if block_indent is None:
                    block_indent = ind
                body.append(raw[block_indent:] if ind >= block_indent else raw.lstrip())
            else:
                body.append("")
            i += 1
        while self.pos < len(self.lines) and self.lines[self.pos][2] < i:
            self.pos += 1
        while body and body[-1] == "":
            body.pop()
        if style[0] == "|":
            text = "\n".join(body)
        else:
            text = re.sub(r"(?<!\n)\n(?!\n)", " ", "\n".join(body))
        return text if style.endswith("-") else text + "\n"


def loads(text: str) -> Any:
    """Parse a YAML-subset document."""
    return _Parser(text).parse()


def load(path: Any) -> Any:
    with open(path, encoding="utf-8") as fh:
        return loads(fh.read())


def split_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    """Split ``---`` frontmatter from a Markdown document."""
    if not text.startswith("---"):
        return {}, text
    lines = text.splitlines()
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            meta = loads("\n".join(lines[1:i])) or {}
            if not isinstance(meta, dict):
                raise YAMLError("frontmatter must be a mapping")
            return meta, "\n".join(lines[i + 1 :]).lstrip("\n")
    raise YAMLError("unterminated frontmatter")
