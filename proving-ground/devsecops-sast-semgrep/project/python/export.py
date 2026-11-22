#!/usr/bin/env python3
"""Export routes: item search and file download."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from flask import Flask, request, send_file

app = Flask(__name__)
DB = os.environ.get("INV_DB", "/tmp/inventory.db")
FILE_ROOT = Path("/srv/exports").resolve()


@app.get("/items")
def items():
    name = request.args.get("name", "")
    conn = sqlite3.connect(DB)
    try:
        rows = conn.execute("SELECT sku, name, price FROM items WHERE name = ?", (name,)).fetchall()
    finally:
        conn.close()
    return {"items": rows}


@app.get("/download")
def download():
    fname = request.args.get("f", "")
    path = (FILE_ROOT / fname).resolve()
    if FILE_ROOT not in path.parents:
        return {"error": "outside export root"}, 400
    return send_file(path)
