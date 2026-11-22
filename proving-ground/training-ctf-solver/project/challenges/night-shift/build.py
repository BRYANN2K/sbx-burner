#!/usr/bin/env python3
"""Build night-shift: build.py <handout-dir>. The flag comes from $CTF_FLAG."""

import importlib.util
import os
import shutil
import sys
from pathlib import Path

here = Path(__file__).resolve().parent
handout = Path(sys.argv[1])
flag = os.environ["CTF_FLAG"].encode()

spec = importlib.util.spec_from_file_location("stream", here / "stream.py")
stream = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stream)

note = b"HANDOVER NOTE 0412\nshift: night\nbadges returned: yes\nfor the day team: " + flag + b"\n"
seed = int.from_bytes(os.urandom(4), "big")
(handout / "message.enc").write_bytes(stream.crypt(note, seed))
shutil.copy(here / "stream.py", handout / "stream.py")
