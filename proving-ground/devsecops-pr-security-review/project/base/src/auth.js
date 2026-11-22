"use strict";

const crypto = require("node:crypto");

function key() {
  const k = process.env.TS_SIGNING_KEY;
  if (!k) throw new Error("TS_SIGNING_KEY is not set");
  return k;
}

function mac(user) {
  return crypto.createHmac("sha256", key()).update(user).digest("hex");
}

function sign(user) {
  return `${user}.${mac(user)}`;
}

function verify(token) {
  const dot = token.lastIndexOf(".");
  if (dot <= 0) return null;
  const user = token.slice(0, dot);
  const given = Buffer.from(token.slice(dot + 1), "hex");
  const expected = Buffer.from(mac(user), "hex");
  if (given.length !== expected.length) return null;
  return crypto.timingSafeEqual(given, expected) ? user : null;
}

function userFromHeader(value) {
  if (!value || !value.startsWith("Bearer ")) return null;
  return verify(value.slice("Bearer ".length).trim());
}

module.exports = { sign, verify, userFromHeader };
