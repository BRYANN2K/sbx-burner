#!/usr/bin/env python3
"""Billing exporter: read a usage CSV and emit a JSON summary."""

from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict


def summarize(rows: list[dict[str, str]]) -> dict[str, float]:
    totals: dict[str, float] = defaultdict(float)
    for row in rows:
        try:
            totals[row["account"]] += float(row["units"])
        except (KeyError, ValueError):
            continue
    return dict(sorted(totals.items()))


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: exporter.py <usage.csv>", file=sys.stderr)
        return 2
    with open(argv[1], newline="") as fh:
        summary = summarize(list(csv.DictReader(fh)))
    print(json.dumps({"accounts": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
