#!/usr/bin/env python3
"""Build field-photo: build.py <handout-dir>. The flag comes from $CTF_FLAG."""

import io
import os
import struct
import sys
import zipfile
import zlib
from pathlib import Path

handout = Path(sys.argv[1])
flag = os.environ["CTF_FLAG"]
WIDTH, HEIGHT = 48, 32


def chunk(kind: bytes, data: bytes) -> bytes:
    body = kind + data
    return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))


rows = b"".join(b"\x00" + bytes((x * 5 + y * 3) % 256 for x in range(WIDTH)) for y in range(HEIGHT))
other = "flag{" + os.urandom(16).hex() + "}"
png = (
    b"\x89PNG\r\n\x1a\n"
    + chunk(b"IHDR", struct.pack(">IIBBBBB", WIDTH, HEIGHT, 8, 0, 0, 0, 0))
    + chunk(b"tEXt", b"Software\x00SurveyCam 2.3")
    + chunk(b"tEXt", b"Comment\x00" + other.encode())
    + chunk(b"IDAT", zlib.compress(rows))
    + chunk(b"IEND", b"")
)

archive = io.BytesIO()
with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("survey/notes.txt", f"Site survey, cabinet 3\nAccess note: {flag}\n")
(handout / "site.png").write_bytes(png + archive.getvalue())
