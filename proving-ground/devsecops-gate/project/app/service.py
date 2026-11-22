#!/usr/bin/env python3
"""Ops service: health + a /diag endpoint using tools.ping."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from tools import ping


class Service(BaseHTTPRequestHandler):
    def _send(self, code: int, body: str, ctype: str = "application/json") -> None:
        data = body.encode()
        self.send_response(code)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        route = urlparse(self.path)
        q = parse_qs(route.query)
        if route.path == "/health":
            self._send(200, '{"status": "ok"}')
        elif route.path == "/diag":
            self._send(200, ping(q.get("host", [""])[0]), "text/plain")
        else:
            self._send(404, '{"error": "no route"}')


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8094), Service).serve_forever()
