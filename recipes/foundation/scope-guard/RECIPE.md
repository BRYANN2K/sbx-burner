---
name: scope-guard
category: foundation
summary: Prove that a scope file is enforced by the sandbox network policy, by probing every in-scope host and a set of canaries that must stay blocked.
risk: low
time: 5m
agents: [claude, codex]
variants:
  linux: beta
  macos: planned
status: beta
licence: Apache-2.0
sources:
  - https://docs.docker.com/ai/sandboxes/security/defaults/
  - https://docs.docker.com/ai/governance/local/network-rules/
  - https://github.com/0xSteph/pentest-ai-agents
---

# scope-guard

Run this before any security recipe. The agent reads the scope file, starts a
tiny web server inside the sandbox on the in-scope port, and probes each
in-scope host and each canary once. The agent also probes each host in the
scope's `network.deny` list: a denied host that answers is the clearest proof
that the policy is not enforced. In-scope hosts must answer. Canaries and
denied hosts must be blocked by the sandbox egress proxy. Any out-of-scope
host that answers is a finding: the scope is not enforced.

## When to use it

- Once on a new machine, before the first security recipe.
- After changing the global sbx policy (`sbx policy init`, `sbx policy reset`).
- With a scope file in `network.mode: additive`: the runner skips its own
  egress probe in that mode, so this recipe is the only check.

## What you get

- `report.md` and `report.json` in `runs/<timestamp>-scope-guard/`.
- `artifacts/probes.jsonl`: one line per probe, expected and observed result.
- `artifacts/policy-summary.md`: a one-page verdict.
- Metrics `in_scope_reachable`, `out_of_scope_blocked`, `out_of_scope_reachable`.

## Run

```console
$ cp recipes/foundation/scope-guard/scope.example.yaml scope.yaml   # edit the dates
$ python -m lab run foundation/scope-guard --scope scope.yaml --dry-run
$ python -m lab run foundation/scope-guard --scope scope.yaml
```

Canaries come from `fixtures/canaries.txt` (`example.com`, `example.org`).
Edit it to add hosts you care about. Never add a host you do not want
contacted: a canary is contacted once if the policy is open.

## If a canary answers

The global sbx policy is not `deny-all`, or the scope is in additive mode on
top of an open policy. Fix it on the host:

```console
$ sbx policy reset          # deletes local rules; TODO(verify): then asks for a preset
$ sbx policy init deny-all  # only when no preset is set yet
```

Then run the recipe again. In strict mode the runner itself refuses to start
the agent when `example.com` answers, so a strict run that reaches the agent
already passed that first probe.

## Evidence

| Artifact | Content |
| --- | --- |
| `artifacts/probes.jsonl` | `host`, `url`, `expected` (`reachable` or `blocked`), `observed`, `curl_exit`, `http_code`, `http_connect` |
| `artifacts/policy-summary.md` | Verdict, counts, and the fix when a canary answered |
| `artifacts/http-server.log` | Log of the in-scope service on `127.0.0.1:8080` |
| `artifacts/scope-hosts.txt` | Scope host entries as parsed from `.lab/scope.json` |

The runner also saves `runs/<id>/policy-log.json` (`sbx policy log --json`,
host side) corroborating each blocked probe.

## Safety

- Each host is contacted once. No port scan, no retry through another port,
  protocol or proxy.
- The only in-scope service is a Python static file server the agent starts
  on `127.0.0.1:8080` and stops at the end.
- The agent never edits `.lab/scope.json` or the sbx policy.

## Variants

- Linux: Docker's built-in Debian agent with `kits/lab-tools`. `curl`, `jq`
  and `python3` are installed from Debian if the image lacks them.
- macOS: planned, through macsbx.

## Licences

| Tool | Licence | How it is used |
| --- | --- | --- |
| curl | curl (MIT-style) | Debian package |
| jq | MIT | Debian package |
| Python 3 | PSF-2.0 | Debian package, `http.server` for the in-scope target |

The idea of a pre-flight scope check comes from 0xSteph/pentest-ai-agents
(MIT). No text is copied.
