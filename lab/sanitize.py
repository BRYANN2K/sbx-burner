"""Strip terminal control from agent-controlled text before it is shown.

The agent writes ask questions, choices, stream text and tool summaries:
all of it is untrusted when a terminal renders it. ``clean_text`` removes
ANSI/CSI/OSC/DCS escape sequences and every C0/C1 control character the
event schema forbids (it keeps ``\\n`` and ``\\t``), and caps the length.
"""

from __future__ import annotations

import re

# OSC ... terminated by BEL or ST; DCS/SOS/PM/APC ... ST; CSI; single ESC.
_ANSI_RE = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC ... terminated by BEL or ST
    r"|\x1b[P^_X][\s\S]*?\x1b\\"  # DCS/SOS/PM/APC ... terminated by ST
    r"|\x1b[\]P^_X][\s\S]*$"  # unterminated OSC/DCS: no payload reaches the display
    r"|\x1b\[[0-9;:?]*[ -/]*[@-~]"  # CSI
    r"|\x1b[@-Z\\-_]"  # single ESC sequences (incl. a stray ST)
)
# C0 except \t (0x09) and \n (0x0a); DEL and C1 (0x80-0x9f).
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

TEXT_LIMIT = 4096
CHOICE_LIMIT = 512
CHOICES_LIMIT = 64


def clean_text(text: object, limit: int = TEXT_LIMIT) -> str:
    """Schema-safe single string: no escapes, no control chars, length cap."""
    s = _ANSI_RE.sub("", str(text))
    s = _CTRL_RE.sub("", s)
    if len(s) > limit:
        s = s[: limit - 1] + "…"
    return s


def clean_choices(values: object, limit: int = CHOICES_LIMIT) -> list[str]:
    """A list of cleaned choice strings, capped at ``limit`` entries."""
    if not isinstance(values, list | tuple):
        return []
    return [clean_text(v, CHOICE_LIMIT) for v in list(values)[:limit]]
