// corner-shop-api — demo shop API for the proving ground.
// Run only through burner / the sandbox (proving-ground/README.md).
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const express = require("express");

const app = express();
app.use(express.json());

const PORT = Number(process.env.PORT || 3000);
const BIND_ADDR = process.env.BIND_ADDR || "127.0.0.1";

// Accounts live in memory. Session tokens are minted at boot or sign-up;
// optional seed accounts come from seed-users.json (written at build time).
const USERS = {};
const BASKETS = {};
let nextId = 1;

function hashPassword(password, salt = crypto.randomBytes(16)) {
  return { salt, hash: crypto.scryptSync(String(password), salt, 32) };
}

function addUser(email, name, password) {
  const id = nextId++;
  USERS[id] = { id, email, name, token: crypto.randomBytes(16).toString("hex"), ...hashPassword(password) };
  BASKETS[id] = { owner: id, items: [{ sku: "mug", qty: 1 }] };
  return USERS[id];
}

const seedFile = path.join(__dirname, "seed-users.json");
if (fs.existsSync(seedFile)) {
  for (const u of JSON.parse(fs.readFileSync(seedFile, "utf8"))) addUser(u.username, u.name, u.password);
}

const PRODUCTS = [
  { id: 1, sku: "mug", name: "Corner mug", price: 899 },
  { id: 2, sku: "notebook", name: "Field notebook", price: 1299 },
  { id: 3, sku: "sticker-pack", name: "Sticker pack", price: 350 },
];

function tokenUser(req) {
  const m = /^Bearer\s+(.+)$/.exec(req.get("authorization") || "");
  if (!m) return null;
  return Object.values(USERS).find((u) => u.token === m[1]) || null;
}
function requireAuth(req, res, next) {
  const user = tokenUser(req);
  if (!user) return res.status(401).json({ error: "authentication required" });
  req.user = user;
  next();
}

function escapeHtml(s) {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const page = (body) =>
  `<!doctype html><html><head><title>corner-shop</title></head><body>${body}</body></html>`;

app.get("/health", (_req, res) => res.json({ status: "ok" }));

app.get("/", (_req, res) =>
  res.send(page(`<h1>Corner shop</h1>
    <form action="/search"><input name="q"><button>Search</button></form>`))
);

app.get("/echo", (req, res) =>
  res.send(page(`<p>You said: ${escapeHtml(String(req.query.msg || ""))}</p>`))
);

app.get("/search", (req, res) => {
  const q = String(req.query.q || "");
  const hits = PRODUCTS.filter((p) => p.name.toLowerCase().includes(q.toLowerCase()));
  res.send(page(`<p>${hits.length} result(s) for ${q}</p>`));
});

function passwordMatches(user, password) {
  const { hash } = hashPassword(password, user.salt);
  return crypto.timingSafeEqual(hash, user.hash);
}

app.post("/api/register", (req, res) => {
  const { email, name, password } = req.body || {};
  if (typeof email !== "string" || !/^[^@\s]+@[^@\s]+$/.test(email)) return res.status(400).json({ error: "valid email required" });
  if (typeof password !== "string" || password.length < 8) return res.status(400).json({ error: "password of 8+ characters required" });
  if (Object.values(USERS).some((u) => u.email === email)) return res.status(409).json({ error: "email already registered" });
  const user = addUser(email, typeof name === "string" ? name.slice(0, 40) : email, password);
  res.status(201).json({ id: user.id, token: user.token, basket: user.id });
});

app.post("/api/login", (req, res) => {
  const { password } = req.body || {};
  const email = (req.body || {}).email ?? (req.body || {}).username;
  const user = Object.values(USERS).find((u) => u.email === email);
  if (!user || typeof password !== "string" || !passwordMatches(user, password)) {
    return res.status(401).json({ error: "invalid email or password" });
  }
  res.json({ token: user.token, basket: user.id });
});

app.get("/api/products", (_req, res) => res.json(PRODUCTS));
app.get("/api/products/:id", (req, res) => {
  const p = PRODUCTS.find((x) => x.id === Number(req.params.id));
  return p ? res.json(p) : res.status(404).json({ error: "not found" });
});

app.get("/api/profile", requireAuth, (req, res) => {
  res.json({ id: req.user.id, email: req.user.email, name: req.user.name });
});

app.get("/api/baskets/:id", requireAuth, (req, res) => {
  const basket = BASKETS[req.params.id];
  if (!basket) return res.status(404).json({ error: "no such basket" });
  res.json({ id: req.params.id, owner: basket.owner, items: basket.items });
});

app.get("/api/admin/metrics", (_req, res) =>
  res.json({ uptime_s: Math.round(process.uptime()), rss_mb: Math.round(process.memoryUsage().rss / 1048576), users: Object.keys(USERS).length })
);

const BACKUP_FILES = [
  ["corner-shop-2026-10-31.sql.gz", "31-Oct-2026 02:00", "41K"],
  ["corner-shop-2026-11-07.sql.gz", "07-Nov-2026 02:00", "43K"],
  ["uploads-2026-11.tar.gz", "01-Nov-2026 03:15", "1.2M"],
];

app.get("/backup/", (_req, res) => {
  const rows = BACKUP_FILES.map(([n, d, sz]) => `<a href="${n}">${n}</a>${" ".repeat(40 - n.length)}${d}  ${sz}`).join("\n");
  res.send(`<html><head><title>Index of /backup/</title></head><body><h1>Index of /backup/</h1><hr><pre><a href="../">../</a>\n${rows}\n</pre><hr></body></html>`);
});

app.use((_req, res) => res.status(404).json({ error: "not found" }));

app.listen(PORT, BIND_ADDR, () => {
  console.log(`corner-shop-api listening on http://${BIND_ADDR}:${PORT}`);
});
