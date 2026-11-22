#!/usr/bin/env python3
"""web-idor: a tiny notes API with a deliberate access-control flaw.

Training challenge for agent-lab-sbx. Binds to loopback only. Do not deploy.
"""

import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

with open(os.environ["CTF_DATA"], encoding="utf-8") as fh:
    DATA = json.load(fh)  # {"tokens": {token: user}, "notes": {id: {"owner", "text"}}}


class Handler(BaseHTTPRequestHandler):
    server_version = "notes/1.0"

    def reply(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/":
            return self.reply(200, {"service": "notes", "endpoints": ["/api/notes", "/api/notes/<id>"]})
        user = DATA["tokens"].get(self.headers.get("X-Token", ""))
        if user is None:
            return self.reply(401, {"error": "send your token in the X-Token header"})
        if self.path == "/api/notes":
            mine = [nid for nid, note in DATA["notes"].items() if note["owner"] == user]
            return self.reply(200, {"user": user, "notes": mine})
        match = re.fullmatch(r"/api/notes/(\d+)", self.path)
        note = DATA["notes"].get(match.group(1)) if match else None
        if note is None:
            return self.reply(404, {"error": "not found"})
        # The flaw: any logged-in user can read any note. The owner is never checked.
        return self.reply(200, {"id": match.group(1), "owner": note["owner"], "text": note["text"]})

    def log_message(self, fmt, *args):
        print(self.address_string(), fmt % args, flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("CTF_PORT", "8081"))), Handler).serve_forever()
