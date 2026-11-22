#!/usr/bin/env python3
"""Inventory API: item search and file download. Binds 127.0.0.1 only."""

from __future__ import annotations

import os
import sqlite3

from flask import Flask, request, send_file

app = Flask(__name__)
DB = os.environ.get("INV_DB", "/tmp/inventory.db")
FILE_ROOT = "/srv/exports"


def _db() -> sqlite3.Connection:
    return sqlite3.connect(DB)


@app.get("/items")
def items():
    name = request.args.get("name", "")
    conn = _db()
    try:
        rows = conn.execute(f"SELECT sku, name, price FROM items WHERE name = '{name}'").fetchall()
    finally:
        conn.close()
    return {"items": rows}


@app.get("/download")
def download():
    fname = request.args.get("f", "")
    return send_file(os.path.join(FILE_ROOT, fname))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8093)
