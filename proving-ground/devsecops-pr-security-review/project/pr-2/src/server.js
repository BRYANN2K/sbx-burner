"use strict";

const http = require("node:http");
const { execFileSync } = require("node:child_process");
const auth = require("./auth");
const db = require("./db");
const { etagFor } = require("./etag");

const REVISION = (() => {
  try {
    return execFileSync("git", ["rev-parse", "--short", "HEAD"], { encoding: "utf8" }).trim();
  } catch {
    return "unknown";
  }
})();

function send(res, status, body, headers = {}) {
  res.writeHead(status, { "Content-Type": "application/json", ...headers });
  res.end(JSON.stringify(body));
}

async function handle(req, res) {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname === "/health") return send(res, 200, { status: "ok" });
  if (url.pathname === "/api/version") return send(res, 200, { revision: REVISION });

  const user = auth.userFromHeader(req.headers.authorization);
  if (!user) return send(res, 401, { error: "authentication required" });

  if (req.method === "GET" && url.pathname === "/api/entries") {
    const body = { entries: await db.entriesFor(user) };
    const tag = etagFor(body);
    if (req.headers["if-none-match"] === tag) {
      res.writeHead(304, { ETag: tag });
      return res.end();
    }
    return send(res, 200, body, { ETag: tag });
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
