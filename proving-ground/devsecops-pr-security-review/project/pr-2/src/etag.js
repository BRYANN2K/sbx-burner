"use strict";

const crypto = require("node:crypto");

// Weak validator for conditional GETs on list responses.
function etagFor(body) {
  const digest = crypto.createHash("md5").update(JSON.stringify(body)).digest("hex");
  return `W/"${digest}"`;
}

module.exports = { etagFor };
