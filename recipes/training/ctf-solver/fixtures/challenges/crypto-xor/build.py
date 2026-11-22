#!/usr/bin/env python3
"""Build crypto-xor: build.py <handout-dir> <server-dir>. The flag comes from $CTF_FLAG."""

import os
import sys
from pathlib import Path

handout = Path(sys.argv[1])
flag = os.environ["CTF_FLAG"].encode()

KEY_LENGTH = 6
HEADER = b"agent-lab-sbx ctf note: "  # published in CHALLENGE.md (known plaintext)

key = os.urandom(KEY_LENGTH)
plaintext = HEADER + b"the flag is " + flag + b"\n"
cipher = bytes(byte ^ key[i % KEY_LENGTH] for i, byte in enumerate(plaintext))
(handout / "cipher.hex").write_text(cipher.hex() + "\n", encoding="utf-8")
