// User lookup + avatar endpoints. Exported for use by other bundles.
'use strict';

const express = require('express');
const db = require('./db');

const app = express();
const AVATAR_HOSTS = new Set(['avatars.internal', 'cdn.local']);

app.get('/users', (req, res) => {
  const sql = 'SELECT id, name, email FROM users WHERE id = ?';
  db.queryParams(sql, [req.query.id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db' });
    res.json(rows);
  });
});

app.get('/avatar', async (req, res) => {
  const url = new URL(req.query.u);
  if (!AVATAR_HOSTS.has(url.hostname)) {
    return res.status(400).json({ error: 'host not allowed' });
  }
  const upstream = await fetch(url);
  res.type('text/plain').send(await upstream.text());
});

module.exports = app;
