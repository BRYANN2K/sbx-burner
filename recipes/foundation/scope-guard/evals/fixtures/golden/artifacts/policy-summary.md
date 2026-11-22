# Scope policy summary

**Verdict: enforced.** Every out-of-scope probe was refused by the egress
proxy and the in-scope service answered.

## Probes

| Host | Expected | Observed | curl exit | HTTP | CONNECT |
| --- | --- | --- | --- | --- | --- |
| localhost:8080 | reachable | reachable | 0 | 200 | 000 |
| example.com | blocked | blocked | 56 | 000 | 403 |
| example.org | blocked | blocked | 56 | 000 | 403 |

## Counts

- In-scope reachable: 1 of 1 literal hosts.
- Out-of-scope blocked: 2 of 2 canaries (0 denied hosts in this scope).
- Out-of-scope reachable: 0.

## Notes

- `*.lab.internal` is covered by the policy but is a wildcard: it was not
  probed, there is no literal name to contact.
- The two canaries were refused at the CONNECT tunnel (`http_connect` 403,
  curl exit 56): the proxy decision, not a service answer.
- Loopback may bypass the egress policy entirely; the `localhost:8080`
  answer shows the service ran, not that policy covers 127.0.0.1.
