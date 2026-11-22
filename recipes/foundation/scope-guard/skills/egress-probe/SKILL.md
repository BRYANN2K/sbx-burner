---
name: egress-probe
description: Verify a lab scope is enforced by the sandbox egress proxy by probing each in-scope host once and each canary once. Use when asked to check scope enforcement, network policy, egress control or canaries in an agent-lab-sbx run.
---

# Egress probe

The question: does the sandbox network policy actually allow the scope hosts
and block everything else? Answer it with traffic, not assumptions. One HTTP
request per host; the raw curl result is the evidence.

## 1. Read the scope

```bash
mkdir -p evidence/artifacts
jq -r '.targets[].hosts[]?' .lab/scope.json   # every scope host entry
jq -r '.network.deny[]?'   .lab/scope.json   # explicitly denied hosts
```

- Literal entries (`localhost:8080`, `app.lab.internal`) are probed once.
- Wildcards (`*.lab.internal`) are never probed: record them in
  `policy-summary.md` as "covered by policy, not probed".
- Denied hosts are probed once, expected `blocked`, like canaries.

## 2. Start the in-scope service

A scope entry for `localhost` or `127.0.0.1` names a service you start
yourself first. For `localhost:8080`:

```bash
python3 -m http.server 8080 --bind 127.0.0.1 --directory fixtures/www \
  > evidence/artifacts/http-server.log 2>&1 &
server_pid=$!
sleep 1
```

TODO(verify): whether loopback traffic inside the sandbox is subject to the
egress policy at all. If it is not, `localhost:8080` answers whatever the
policy says — record the result and note it in `policy-summary.md`; it does
not prove enforcement.

## 3. Probe once per host

Scheme: explicit port other than 443 → `http://`; no port or port 443 →
`https://` (the runner's own egress probe uses the same HTTPS default).

```bash
probe() { # host expected -> one probes.jsonl line
  local host="$1" expected="$2" url port codes rc http_code http_connect observed
  case "$host" in *:*) port="${host##*:}" ;; *) port=443 ;; esac
  if [ "$port" = "443" ]; then url="https://${host}/"; else url="http://${host}/"; fi
  codes="$(curl -sS -o /dev/null -m 10 -w '%{http_code} %{http_connect}' "$url" 2>/dev/null)"; rc=$?
  http_code="${codes% *}"; http_connect="${codes#* }"
  if [ "$rc" -ne 0 ] || [ "$http_code" = "403" ] || [ "$http_connect" = "403" ]; then
    observed=blocked
  else
    observed=reachable
  fi
  jq -cn --arg host "$host" --arg url "$url" --arg expected "$expected" \
    --arg observed "$observed" --argjson curl_exit "$rc" \
    --arg http_code "$http_code" --arg http_connect "$http_connect" \
    '{host:$host,url:$url,expected:$expected,observed:$observed,curl_exit:$curl_exit,http_code:$http_code,http_connect:$http_connect}' \
    >> evidence/artifacts/probes.jsonl
}
```

Blocked means: **curl exits non-zero OR the proxy answers HTTP 403**.
Record `curl_exit`, `http_code` and `http_connect` raw — they distinguish
the cases:

- `rc` non-zero, `http_code` `000`: connection refused or reset.
- `rc` non-zero, `http_connect` `403`: the proxy refused the CONNECT tunnel.
- `rc` zero, `http_code` `403`: an HTTP 403 came back. It may be the proxy's
  refusal page or the service's own 403 — the two cannot be told apart, so
  this still counts as blocked; the raw values stay in the line.

TODO(verify): the exact response the sbx egress proxy returns for a refused
request (403 expected; the docs say "HTTP 403, a connection failure, or
another service error").

## 4. Verdict and summary

Write `evidence/artifacts/policy-summary.md`:

- Verdict `enforced` when every expected-`blocked` probe is blocked and
  every in-scope literal host answered; `not enforced` the moment one
  out-of-scope host answers; `inconclusive` when an in-scope host is down.
- Counts: `in_scope_reachable`, `out_of_scope_blocked`,
  `out_of_scope_reachable` — the same values go to `metrics`.
- Wildcard entries listed as covered-but-not-probed.
- When a canary answered, the fix on the host:

  ```console
  $ sbx policy reset            # clears local rules; TODO(verify): asks for a preset
  $ sbx policy init deny-all    # when no preset is set yet
  ```

  In `network.mode: additive` the runner skips its own egress probe, so a
  canary answering there may mean the global policy is `open`.
- Known limit from the sbx docs: rules match the attributed hostname (TLS
  SNI or HTTP `Host`), so a denied host sharing an IP with an allowed host
  can still answer. Say so when a canary is reached.
- The runner saves `sbx policy log <sandbox> --json` to
  `runs/<id>/policy-log.json` (on the host, outside the sandbox); it
  corroborates each blocked probe. TODO(verify): its exact JSON shape.

Stop the service before finishing: `kill "$server_pid"`.

## Pitfalls

- Retrying a blocked host on another port or protocol. One probe, then
  record.
- Following a 301/302 to a host that is not in the list: `curl` without `-L`.
- Treating curl exit 0 as success. A proxy 403 exits 0 without `-f`; the
  classification above is what matters.
- Probing `https://` on a plain-HTTP lab port and calling the host down:
  pick the scheme from the port, step 3.
- A wildcard is not a host. `*.lab.internal` is covered by the policy; there
  is nothing to curl.
- Forgetting to stop `http.server`: the sandbox is destroyed at the end of
  the run, but the report's tool list must match what actually ran.
