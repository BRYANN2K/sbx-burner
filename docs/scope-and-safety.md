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
schema_version: "1"
id: juice-shop-practice
owner: Your Name
authorization:
  type: own-lab               # or "written", with a reference
valid:
  not_before: "2026-11-21"
  not_after: "2026-11-28"
targets:
  - name: juice-shop
    hosts:
      - localhost:3000
network:
  mode: strict
  allow: []
  deny: []
techniques:
  allowed: [recon, scan, content-discovery]
  forbidden: [exploit, brute-force]
notes: Practice run on my own lab.
```

For a third-party target, use written authorization:

```yaml
authorization:
  type: written
  reference: https://example.com/security   # contract, ticket or program policy
```

The runner validates the file against `lab/schema/scope.schema.json` and refuses any other key. Check a file with `python -m lab scope scope.yaml --host app.example.com`.

| Field | Meaning |
|---|---|
| `schema_version` | Always `"1"`. |
| `id` | Short name, lowercase letters, digits and dashes. Used in the report. |
| `owner` | Who runs the test. |
| `authorization` | `type` is `own-lab` or `written`. `written` needs a `reference`. `contact` is optional. |
| `valid` | `not_before` and `not_after`, quoted `YYYY-MM-DD` dates. The runner refuses to start outside the window. The window is at most one year. |
| `targets` | At least one. Each has a `name` and `hosts` (`host`, `host:port` or CIDR) or `paths`. |
| `network` | `mode` is `strict` (default) or `additive`. `allow` adds hosts. `deny` hosts are never allowed and win over `allow` and `targets`. |
| `techniques` | `allowed` (at least one), `forbidden`, and `risky`: the risky techniques you allow on purpose (see below). |
| `notes` | Free text. |

Rules the runner enforces:

- `own-lab` covers only `localhost`, private IP ranges and the names `.localhost`, `.test`, `.internal`, `.lab`, `.local`, `.example` and `.home.arpa`. A public host needs `authorization.type: written` with a `reference`.
- A CIDR is at most `/16` for IPv4 and `/48` for IPv6.
- A bare `*` or `**` is refused.
- A wildcard that covers a whole top-level domain is refused. `*.com` fails. `*.lab` is allowed.
- A URL is not a host. Write `app.example.com`, not `https://app.example.com`.
- No technique is refused outright by the scope file. Risky techniques are off unless you allow them, and each one you allow must also be listed under `techniques.risky`:
  - aimed at hosts: `brute-force`, `lockout-testing`, `credential-reuse`, `dos`, `ddos`, `data-destruction`, `ransomware`. They need `authorization.type: written` with a `reference`, unless every target is local to the sandbox (`localhost`, `127.0.0.0/8`, `::1`);
  - aimed at people: `social-engineering`, `phishing`, `physical`. They always need `authorization.type: written` with a `reference`.
- You are responsible for the authorization behind every technique you allow. The acknowledged risky techniques are written in `TASK.md` and in `report.json` (`run.scope.risky_acknowledged`).

Allowing a technique in a scope does not make a recipe use it:

- the network policy still reaches only the scope hosts (plus the agent API and tool hosts), whatever the techniques say;
- each recipe's `AGENTS.md` keeps its own list of things the agent never does, and that list still applies.

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

## Target kinds and scope

Recipes test your target. These rules keep each kind inside the scope. See [Choose your target](getting-started.md#5-choose-your-target).

- `--target-url` needs `--scope`. Its host must already be in the scope file. The runner never adds it. A public host needs `authorization.type: written` with a `reference`.
- `--target-port` adds only `localhost:HOST`. It is marked "added by runner" in `TASK.md` and in the report. The runner changes the in-memory scope only. It never rewrites your scope file.
- Your container shares the sandbox egress policy. While it runs, it can reach whatever the allow-list holds, the agent API host included.
- Package and registry hosts (`--target-app` installs, a sandbox image pull) are install-only. They are opened for the install window and closed before the agent starts. They are never in the allow-list.
- Your credentials stay on the host. Repos are cloned and images are pulled with your own git and Docker logins. The sandbox gets the result only. Agent credentials go through `sbx secret`. A URL with credentials is refused.
- Dependency lifecycle scripts (npm `postinstall` and similar) run inside the sandbox during the install window, never on your machine.

## Security model

The agent runs with every permission inside the sandbox. It has no approval prompts and the agent user has passwordless sudo. The boundary is the sandbox, not the agent's behaviour:

- microVM isolation from your machine,
- a network policy built from the scope, with install hosts closed before the agent starts,
- credentials injected by the `sbx` proxy, never visible in the VM,
- your target mounted read-only (`path`, `repo`) or copied (`app`).

This model relies on two `sbx` properties that are not yet verified:

- The network policy is enforced outside the guest, so root in the VM cannot lift it. <!-- TODO(verify): confirm in the sbx docs or by test. -->
- The read-only target mount is enforced by the host, so root in the VM cannot remount it read-write. <!-- TODO(verify): confirm in the sbx docs or by test. -->

`lab-ask` is a convenience, not a boundary. The agent could write an answer file itself, so the runner records every answer on the host and flags any it did not write. See [Live runs](live-runs.md).

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
