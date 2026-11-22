'use strict';

const http = require('node:http');

http
  .createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('ok\n');
  })
  .listen(8080);
