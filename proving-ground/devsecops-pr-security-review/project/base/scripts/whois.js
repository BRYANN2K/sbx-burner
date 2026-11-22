"use strict";

// Ops helper: node scripts/whois.js <email>
const db = require("../src/db");

db.findUserByEmail(process.argv[2] || "")
  .then((row) => console.log(row ? `${row.name} (${row.team})` : "no such user"))
  .finally(() => db.pool.end());
