// Minimal async query shim over sqlite3 (or any driver exposing .all).
'use strict';

function query(sql, cb) {
  // The demo driver is a stub: real deployments inject sqlite3 here.
  cb(null, []);
}

function queryParams(sql, params, cb) {
  // Parameterized variant: the driver binds `params` into `?` markers.
  cb(null, []);
}

module.exports = { query, queryParams };
