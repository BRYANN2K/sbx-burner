# Scope and safety

Security recipes work only on targets you are allowed to test. A scope file says which. The sandbox network enforces it.

## Rules

- Defensive work and authorized testing only.
- Every security recipe needs a scope file. The runner refuses to start without one.
- Default targets are labs you start yourself. A third-party target needs written authorization, cited in the scope file.
- Scope is enforced by `sbx` network policy, not only by the agent's instructions.
- Findings need proof. See [Evidence and reports](evidence-and-reports.md).
- Malware samples are never committed. They enter the sandbox at run time and the sandbox is destroyed after.

## The scope file

`scope.example.yaml` ships with each security recipe. Copy it, edit it, pass it with `--scope`.

```yaml
# scope.yaml
engagement: vuln-lab-practice
authorization: self-owned lab        # or a reference to written authorization
dates:
  start: 2026-11-21
  end: 2026-11-28
targets:
  - name: juice-shop
    hosts: [juice-shop.lab.internal]
    ports: [3000]
allowed_techniques:
  - passive-recon
  - web-app-testing
forbidden_techniques:
  - denial-of-service
  - social-engineering
  - data-destruction
out_of_scope:
  - hosts: ["*.example.com"]
```

The field names above are the intended contract. The runner validates them. A recipe may add recipe-specific keys.

| Field | Meaning |
|---|---|
| `engagement` | Short name. Used in the report. |
| `authorization` | Who allowed this, or "self-owned lab". |
| `dates` | The runner refuses to start outside the window. |
| `targets` | Hosts and ports the agent may reach. |
| `allowed_techniques` | Techniques the agent may use. |
| `forbidden_techniques` | Always off. |
| `out_of_scope` | Explicit exclusions. They win over `targets`. |

## How scope is enforced

Three layers. Each one works without the others.

1. **Network.** The runner turns `targets` into `sbx` network policy rules. The sandbox cannot reach other hosts. Egress is denied by default in `sbx`, and the runner adds only the scope hosts plus what the agent needs to run.
2. **Agent instructions.** `AGENTS.md` tells the agent to read the scope file first and to stop on any out-of-scope request.
3. **Report.** The report lists what was contacted. A contact outside the scope fails the run.

Commands involved:

```sh
sbx policy ls
sbx policy allow network <host>
sbx policy deny network <host>
```

<!-- TODO(verify): confirm the exact host and port syntax accepted by `sbx policy allow network`, and whether policy can be set per sandbox or only globally. The docs say the policy is global; the runner design must handle that. -->

`sbx` policy is global to the installation. The runner reports the policy it set and warns when it changes an existing one. <!-- TODO(verify): confirm global vs per-sandbox policy scope in the sbx docs. -->

## Offline recipes

Malware and some detection recipes need no outbound access. They run with the network denied and an optional local sinkhole for DNS and HTTP. Nothing leaves the host.

## Credentials

Agent credentials stay on the host. The sandbox sees a placeholder. The runner never reads or prints a key. Cloud audit recipes pass credentials only through `sbx secret`.

## Stop conditions

The agent stops and reports when:

- a request falls outside the scope,
- a finding has no proof after the budget is spent,
- a target behaves unexpectedly (data loss, outage),
- the scope dates have passed.

## What we will not accept

See "Acceptable use" in [SECURITY.md](../SECURITY.md).
