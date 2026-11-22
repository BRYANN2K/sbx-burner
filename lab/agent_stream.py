"""Normalize the agents' machine-readable streams into run events.

Each normalizer takes one stdout line from the agent step and returns
``(events, skipped)``: ``events`` is a list of ``(type, fields)`` pairs
ready for ``EventWriter.emit``; ``skipped`` counts upstream events the
normalizer does not understand. Unknown input — malformed JSON, unknown
upstream types — is skipped and counted, never raised.

Stream flags (marked TODO(verify) where they sit in lab/sbx.py):
Claude Code ``-p --output-format stream-json --verbose``; Codex
``exec --json``.
"""

from __future__ import annotations

import json
from typing import Any


def _tool_summary(name: str, inp: Any) -> str:
    """One-line summary of a tool call: command head or a file path."""
    if isinstance(inp, str) and inp.strip():
        return inp.strip().splitlines()[0]
    if isinstance(inp, dict):
        for key in ("command", "cmd", "file_path", "path", "url", "query"):
            value = inp.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip().splitlines()[0]
        for value in inp.values():
            if isinstance(value, str) and value.strip():
                return value.strip().splitlines()[0]
    return name


def from_claude_stream_json(line: str) -> tuple[list[tuple[str, dict[str, Any]]], int]:
    """Claude Code ``stream-json``: ``assistant`` messages carry content
    blocks; ``text`` -> agent.message, ``tool_use`` -> agent.tool.
    Everything else (system, user, result, rate limits) is skipped."""
    line = line.strip()
    if not line:
        return [], 0
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return [], 1
    if not isinstance(obj, dict):
        return [], 1
    events: list[tuple[str, dict[str, Any]]] = []
    if obj.get("type") == "assistant":
        message = obj.get("message") or {}
        content = message.get("content") or []
        for block in content if isinstance(content, list) else []:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text" and isinstance(block.get("text"), str):
                events.append(("agent.message", {"agent": "claude", "text": block["text"]}))
            elif block.get("type") == "tool_use":
                name = str(block.get("name", "tool"))
                events.append(("agent.tool", {"agent": "claude", "tool": name, "summary": _tool_summary(name, block.get("input"))}))
        return events, 0
    # user/tool_result/system/result lines: known but not shown as agent output.
    return [], 1


def from_codex_json(line: str) -> tuple[list[tuple[str, dict[str, Any]]], int]:
    """Codex ``exec --json``: ``item.*`` events wrap items; agent_message
    text -> agent.message, command/tool items -> agent.tool. Lifecycle
    events (thread/turn/usage) are skipped."""
    line = line.strip()
    if not line:
        return [], 0
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return [], 1
    if not isinstance(obj, dict):
        return [], 1
    events: list[tuple[str, dict[str, Any]]] = []
    item = obj.get("item")
    if obj.get("type") in ("item.completed", "item.started") and isinstance(item, dict):
        kind = item.get("type")
        if kind == "agent_message" and isinstance(item.get("text"), str):
            events.append(("agent.message", {"agent": "codex", "text": item["text"]}))
            return events, 0
        if kind in ("command_execution", "shell_command", "tool_call", "mcp_tool_call", "function_call"):
            name = str(item.get("tool") or item.get("name") or "exec")
            summary = item.get("command") or item.get("input") or name
            events.append(("agent.tool", {"agent": "codex", "tool": name, "summary": _tool_summary(name, summary)}))
            return events, 0
        return [], 1
    return [], 1


_NORMALIZERS = {
    "claude": from_claude_stream_json,
    "codex": from_codex_json,
}


def for_agent(name: str):
    """The normalizer matching the agent's stream flags."""
    return _NORMALIZERS.get(name, lambda line: ([], 1))
