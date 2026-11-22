// Tiny status board: serves uptime counters as JSON on 127.0.0.1:8090.
'use strict';

const http = require('http');
const minimist = require('minimist');
const _ = require('lodash');

const argv = minimist(process.argv.slice(2), { default: { port: 8090 } });
const counters = { requests: 0, started: Date.now() };

const server = http.createServer((req, res) => {
  counters.requests += 1;
  const body = JSON.stringify(_.merge({}, counters, { host: 'localhost' }));
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(body);
});

server.listen(argv.port, '127.0.0.1', () => {
  console.log(`status board on 127.0.0.1:${argv.port}`);
});
