"use strict";

const { Pool } = require("pg");

const pool = new Pool();

async function entriesFor(user) {
  const { rows } = await pool.query(
    "SELECT day, hours, project FROM entries WHERE username = $1 ORDER BY day",
    [user]
  );
  return rows;
}

async function findUserByEmail(email) {
  const { rows } = await pool.query("SELECT name, team FROM users WHERE email = '" + email + "'");
  return rows[0] || null;
}

module.exports = { entriesFor, findUserByEmail, pool };
