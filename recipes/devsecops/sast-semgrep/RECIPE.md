---
name: sast-semgrep
category: devsecops
summary: Static-analyse a codebase with semgrep and a small set of bundled original rules, confirming every hit against the code before reporting.
risk: low
time: 15m
variants:
  linux: beta
  macos: planned
status: beta
licence: Apache-2.0
sources:
  - https://github.com/semgrep/semgrep
  - https://semgrep.dev/docs/
---

# sast-semgrep

The agent runs semgrep on the target codebase with the recipe's bundled
original rules (`fixtures/rules/`), reads the code path of every hit, and
reports only the confirmed issues. Registry rule packs are optional and
fetched at run time; they are never vendored. The default network policy
is fully closed: `semgrep.dev` is reachable only if you add
`semgrep.dev:443` to `run.network.allow` in your own copy of the recipe.

## When to use it

- Before merging a feature, to catch injection and dangerous-config
  patterns early.
- When auditing an unfamiliar codebase.
- As the SAST step of `devsecops/gate`.

## What you get

- `report.md` and `report.json` in `runs/<timestamp>-sast-semgrep/`.
- One finding per confirmed issue, with the rule id, `file:line`, severity
  and the fix.
- Dismissed hits (test code, sanitised input, unreachable paths) listed as
  hypotheses with the reason.

## Run

```console
$ python -m lab run devsecops/sast-semgrep --target ./my-app --dry-run
$ python -m lab run devsecops/sast-semgrep --target ./my-app
$ python -m lab run devsecops/sast-semgrep --target-repo owner/my-repo@main
```

The target is a local folder (`--target PATH`) or a git repository
(`--target-repo SRC[@REF]`: `owner/repo`, an https or ssh URL). The runner
clones a repository on the host with your own git login, so private
repositories work and no credential enters the sandbox. Either way it is
mounted read-only at `/home/agent/target`. No scope file is
needed: the recipe reads files and contacts no target host.

To try it on a planted target:

```console
$ bash recipes/devsecops/sast-semgrep/evals/make-target.sh /tmp/sast-demo
$ python -m lab run devsecops/sast-semgrep --target /tmp/sast-demo
$ python -m lab eval devsecops/sast-semgrep --run runs/<id>
```

## Evidence

| Artifact | Content |
| --- | --- |
| `artifacts/semgrep.json` | Raw semgrep report |
| `artifacts/semgrep.sarif` | The same report as SARIF, for code scanning |

## Safety

- Static analysis only: the agent never runs or builds the target's code.
- Semgrep runs with `--metrics=off`; no code or metrics leave the sandbox.
- Registry rules are code. The bundled rules are original and reviewed;
  fetching other people's rules at run time is optional, and the agent
  reads a rule before trusting its hits.

## Variants

- Linux: Docker's built-in Debian agent with the `kits/devsecops` toolbox;
  semgrep is installed by `tools/install.sh` through pipx.
- macOS: planned, through macsbx.

## Licences

| Tool | Licence | How it is used |
| --- | --- | --- |
| semgrep 1.186.0 | LGPL-2.1 | Installed with pipx at run time and only executed; never vendored or linked |
| `fixtures/rules/` | Apache-2.0 | Original rules written for this repository |

Semgrep registry rules are under the Semgrep Rules License: they may be
fetched and run, but not redistributed. This recipe links to the registry
and never copies its rules.
