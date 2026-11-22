#!/usr/bin/env python3
"""Build web-idor: build.py <handout-dir> <server-dir>. The flag comes from $CTF_FLAG."""

import json
import os
import secrets
import sys
from pathlib import Path

handout, server = Path(sys.argv[1]), Path(sys.argv[2])
flag = os.environ["CTF_FLAG"]

guest_token = secrets.token_hex(12)
admin_token = secrets.token_hex(12)
data = {
    "tokens": {guest_token: "guest", admin_token: "admin"},
    "notes": {
        "1001": {"owner": "admin", "text": f"Release checklist. Flag: {flag}"},
        "1002": {"owner": "guest", "text": "Welcome, guest. This is your first note."},
        "1003": {"owner": "guest", "text": "Reminder: notes are private to their owner."},
    },
}
(server / "notes.json").write_text(json.dumps(data), encoding="utf-8")
os.chmod(server / "notes.json", 0o600)
(handout / "guest-token.txt").write_text(guest_token + "\n", encoding="utf-8")
