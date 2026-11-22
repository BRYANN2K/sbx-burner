#!/usr/bin/env python3
"""Webhook forwarder: accepts JSON on /hook and forwards it upstream."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

import requests
from jinja2 import Template

UPSTREAM_URL = "http://127.0.0.1:9099/events"
TEMPLATE = Template("forwarded {{ count }} events")


class Hook(BaseHTTPRequestHandler):
    count = 0

    def do_POST(self) -> None:
        if self.path != "/hook":
            self.send_error(404)
            return
        length = int(self.headers.get("content-length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        Hook.count += 1
        requests.post(UPSTREAM_URL, json={"payload": payload, "n": Hook.count}, timeout=5)
        body = TEMPLATE.render(count=Hook.count).encode()
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8091), Hook).serve_forever()
