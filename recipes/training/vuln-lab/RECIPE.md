---
name: vuln-lab
category: training
summary: Start OWASP Juice Shop and DVWA inside the sandbox, prove three well-known training flaws with saved requests and responses, then reset the lab.
risk: medium
time: 25m
variants:
  linux: beta
  macos: planned
status: beta
licence: Apache-2.0
sources:
  - https://github.com/juice-shop/juice-shop
  - https://github.com/digininja/DVWA
  - https://owasp.org/www-project-web-security-testing-guide/
---

# vuln-lab

The agent starts two deliberately vulnerable web applications with the
sandbox's private Docker Engine, waits until both answer, and proves a short
list of textbook flaws against them. Each proof is one request and one saved
response. The lab is then removed with its volumes.

This recipe is the reference target for the `pentest/*` recipes: their evals
expect the same applications on the same ports.

## When to use it

- To learn how the lab runner, the scope file and the evidence gate work on a
  target that cannot hurt anyone.
- To check that a sandbox can pull images and reach `localhost` targets before
  running a pentest recipe.
- To practise writing a finding with a minimal proof of concept.

## What you get

- `report.md` and `report.json` in `runs/<timestamp>-vuln-lab/`.
- Three findings, each with a request file and a response file:
  Juice Shop login SQL injection, DVWA reflected XSS, DVWA command injection.
- One hypothesis for the Juice Shop DOM XSS, which a plain HTTP client cannot
  prove.
- A start log and a reset log for the lab.

## Run

```console
$ cp recipes/training/vuln-lab/scope.example.yaml scope.yaml   # set owner and dates
$ python -m lab run training/vuln-lab --scope scope.yaml --dry-run
$ python -m lab run training/vuln-lab --scope scope.yaml
```

The targets are `localhost:3000` (Juice Shop) and `localhost:8081` (DVWA),
both inside the sandbox. The images are pulled by `tools/install.sh` on
install-only hosts that are closed before the agent starts: during the
agent step only the two lab ports and the agent API are reachable.

## Evidence

| Artifact | Content |
| --- | --- |
| `artifacts/lab-health.txt` | Output of `lab.sh up`, `wait` and `status`, plus the Juice Shop version |
| `artifacts/<ID>-request.txt` | The exact request of each proof |
| `artifacts/<ID>-response.txt` | The response, with session tokens masked |
| `artifacts/<ID>-control-response.txt` | The same request without the payload |
| `artifacts/reset.txt` | Output of `fixtures/lab.sh reset` (`compose down -v`) |

## Safety

- Targets are containers started by this recipe and bound to `127.0.0.1`
  inside the sandbox. The scope example lists only those two ports.
- The agent proves each flaw once and stops. It never dumps tables, never
  reads files beyond the command `id`, never keeps a shell.
- No denial of service, no brute force, no scanning of other hosts.
- The DVWA database password is generated at start and never stored in the
  repository.

## Variants

- Linux: `kalilinux/kali-rolling` through `kits/base-kali`, with
  `kits/lab-tools`. Only `curl`, `jq` and Docker are needed.
- macOS: planned, through macsbx.

## Licences

| Tool | Licence | How it is used |
| --- | --- | --- |
| OWASP Juice Shop v20.4.0 | MIT | Container image pulled and run at run time |
| DVWA | GPL-3.0 | Container image pulled and run at run time only; never vendored |
| MariaDB 10.11 | GPL-2.0 | Container image pulled and run at run time only; never vendored |
| curl, jq | curl licence, MIT | Kali packages |
