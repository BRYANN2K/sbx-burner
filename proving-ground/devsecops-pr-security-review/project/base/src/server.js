"use strict";

const http = require("node:http");
const auth = require("./auth");
const db = require("./db");

function send(res, status, body, headers = {}) {
  res.writeHead(status, { "Content-Type": "application/json", ...headers });
  res.end(JSON.stringify(body));
}

async function handle(req, res) {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname === "/health") return send(res, 200, { status: "ok" });

  const user = auth.userFromHeader(req.headers.authorization);
  if (!user) return send(res, 401, { error: "authentication required" });

  if (req.method === "GET" && url.pathname === "/api/entries") {
    return send(res, 200, { entries: await db.entriesFor(user) });
  }
  return send(res, 404, { error: "not found" });
}

const server = http.createServer((req, res) => {
  handle(req, res).catch(() => send(res, 500, { error: "internal error" }));
});

if (require.main === module) {
  server.listen(Number(process.env.PORT || 8080), "127.0.0.1");
}

module.exports = { server, handle };
