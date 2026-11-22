#!/usr/bin/env python3
"""Build forensics-meta: build.py <handout-dir> <server-dir>. The flag comes from $CTF_FLAG.

Writes a small grey PNG whose tEXt "Comment" chunk holds the flag, base64 encoded.
"""

import base64
import os
import struct
import sys
import zlib
from pathlib import Path

handout = Path(sys.argv[1])
flag = os.environ["CTF_FLAG"].encode()


def chunk(kind: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))


size = 16
header = struct.pack(">IIBBBBB", size, size, 8, 0, 0, 0, 0)  # 8-bit greyscale
pixels = b"".join(b"\x00" + bytes([0x80]) * size for _ in range(size))
png = (
    b"\x89PNG\r\n\x1a\n"
    + chunk(b"IHDR", header)
    + chunk(b"tEXt", b"Software\x00agent-lab-sbx ctf")
    + chunk(b"tEXt", b"Comment\x00" + base64.b64encode(flag))
    + chunk(b"IDAT", zlib.compress(pixels))
    + chunk(b"IEND", b"")
)
(handout / "photo.png").write_bytes(png)
