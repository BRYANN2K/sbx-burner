#!/usr/bin/env python3
"""Handover-note cipher used by the ops team.

    python3 stream.py <seed> <infile> <outfile>

XORs the input with a keystream drawn from a 32-bit state. The same call
decrypts.
"""

import sys

MUL = 1103515245
INC = 12345


def keystream(seed: int):
    state = seed & 0xFFFFFFFF
    while True:
        state = (MUL * state + INC) & 0xFFFFFFFF
        yield (state >> 16) & 0xFF


def crypt(data: bytes, seed: int) -> bytes:
    ks = keystream(seed)
    return bytes(b ^ next(ks) for b in data)


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    seed = int(argv[1], 0)
    with open(argv[2], "rb") as fh:
        data = fh.read()
    with open(argv[3], "wb") as fh:
        fh.write(crypt(data, seed))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
