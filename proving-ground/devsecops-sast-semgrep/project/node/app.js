// Tiny Express service: user lookup + avatar proxy. Runs on 127.0.0.1 only.
'use strict';

const express = require('express');
const db = require('./db');

const app = express();

// GET /users?id=1 -> row for that user id
app.get('/users', (req, res) => {
  const sql = 'SELECT id, name, email FROM users WHERE id = ' + req.query.id;
  db.query(sql, (err, rows) => {
    if (err) return res.status(500).json({ error: 'db' });
    res.json(rows);
  });
});

// GET /proxy?u=<url> -> fetch a URL for the caller
app.get('/proxy', async (req, res) => {
  const upstream = await fetch(req.query.u);
  const body = await upstream.text();
  res.type('text/plain').send(body);
});

app.listen(8092, '127.0.0.1');
module.exports = app;
