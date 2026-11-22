// Minimal webhook delivery client: queues outbound posts locally.
const calls = [];

function post(endpoint, body) {
  calls.push({ endpoint, body });
  return Promise.resolve({ ok: true, endpoint });
}

module.exports = { post, calls };
