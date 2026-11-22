"use strict";

const test = require("node:test");
const assert = require("node:assert");

process.env.TS_SIGNING_KEY = "unit-test-signing-key";
const auth = require("../src/auth");

test("a mobile 1.x session resolves to its account", () => {
  assert.strictEqual(auth.userFromHeader("Bearer m1:ada"), "ada");
});

test("an empty mobile session is refused", () => {
  assert.strictEqual(auth.userFromHeader("Bearer m1:"), null);
});

test("signed sessions still work", () => {
  assert.strictEqual(auth.userFromHeader(`Bearer ${auth.sign("ben")}`), "ben");
});
