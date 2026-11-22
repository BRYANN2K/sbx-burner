"use strict";

const test = require("node:test");
const assert = require("node:assert");

process.env.TS_SIGNING_KEY = "unit-test-signing-key";
const auth = require("../src/auth");

test("a signed token verifies", () => {
  assert.strictEqual(auth.verify(auth.sign("ada")), "ada");
});

test("a tampered token is refused", () => {
  const token = auth.sign("ada").replace(/^ada/, "ben");
  assert.strictEqual(auth.verify(token), null);
});

test("the header needs the Bearer scheme", () => {
  assert.strictEqual(auth.userFromHeader(auth.sign("ada")), null);
});
