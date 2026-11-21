# Recipe format

A recipe is a folder. The runner reads it, builds a sandbox, starts an agent and collects evidence.

## Layout

```
recipes/<category>/<name>/
├── RECIPE.md          # frontmatter: name, category, summary, risk (low|medium|high), time, agents, variants, status, licence, sources
├── recipe.yaml        # variants: linux {kit, image, sbxenv}, macos {status: planned}
├── AGENTS.md          # role, scope rules, allowed tools, evidence format, stop conditions
├── scope.example.yaml # targets, hosts, allowed techniques, dates (security recipes)
├── sbxenv.yaml        # stock sbx project file for the linux variant
├── skills/            # SKILL.md files
├── tools/             # install scripts (pinned versions)
├── run.py             # entry point using the lab runner
└── evals/             # checks that the recipe produces its evidence
```

`template/` holds a starting copy. The `recipe-lint` CI job checks every recipe against this contract.

## Categories

`foundation`, `devsecops`, `training`, `pentest`, `malware`, `detection`, `hardening`, `ir`, `ai-security`, `dev`, `ci`, `web`, `cu`, `apple` (macOS, planned).

## RECIPE.md

Markdown with YAML frontmatter. The frontmatter feeds the README gallery. The body explains the recipe to a human.

| Field | Meaning |
|---|---|
| `name` | Folder name. Lowercase, dashes. |
| `category` | One of the categories above. |
| `summary` | One sentence. |
| `risk` | `low`, `medium` or `high`. How much harm a mistake could do. |
| `time` | Typical run time, for example `10 min`. |
| `agents` | Agents the recipe was tested with: `claude`, `codex`. |
| `variants` | `linux`, `macos`. |
| `status` | For example `planned`, `experimental`, `stable`. |
| `licence` | SPDX id of the recipe itself. |
| `sources` | Upstream projects and their licences. Anything vendored or inspired by. |

Example:

```yaml
---
name: secrets-scan
category: devsecops
summary: Find committed secrets in a repository and its history.
risk: low
time: 10 min
agents: [claude, codex]
variants: [linux]
status: experimental
licence: Apache-2.0
sources:
  - name: gitleaks
    url: https://github.com/gitleaks/gitleaks
    licence: MIT
---
```

## recipe.yaml

Describes how to run each variant.

```yaml
variants:
  linux:
    kit: <kit name or path>
    image: <OCI image>
    sbxenv: sbxenv.yaml
  macos:
    status: planned
```

- `kit` is the `sbx` kit that installs the tools.
- `image` is the base image for the sandbox.
- `sbxenv` points to the project file in the recipe folder.
- `macos` stays `status: planned` until macsbx can run the recipe.

## AGENTS.md

The instructions the agent reads. Keep it short and strict. It has:

- **Role.** What the agent does.
- **Scope rules.** It reads the scope file first. It refuses anything outside it.
- **Allowed tools.** The tools it may run.
- **Evidence format.** What a finding must contain. See [Evidence and reports](evidence-and-reports.md).
- **Stop conditions.** When to stop and ask: out-of-scope request, no proof, budget spent.

## scope.example.yaml

Required for security recipes. An example the user copies and edits. See [Scope and safety](scope-and-safety.md).

## sbxenv.yaml

The stock `sbx` project file for the Linux variant: agent, kits, workspace, environment. It uses the standard `sbx` grammar and nothing custom. The `sbx env` commands read it. <!-- TODO(verify): the sbx docs list `sbx env create|plan|run|exec|rm` but I found no page describing the sbxenv.yaml schema. Confirm field names before documenting them. -->

## skills/

One folder per skill, each with a `SKILL.md`. Skills hold the method: how to test one class of issue, how to triage, how to write the report.

## tools/

Install scripts. Pin every version. Pull GPL and AGPL tools from their upstream at install time. Never copy them into the repo.

## run.py

The entry point. It uses the lab runner and adds recipe-specific steps. It must work with `--dry-run`.

## evals/

Checks that the recipe produces its evidence. For example: run against a known-vulnerable lab and assert the report lists the known finding with proof. A recipe without a passing eval is not merged.

## Runner

```
python -m lab run <recipe> [--scope file] [--agent claude|codex] [--dry-run]
```

- Python 3.11+, standard library only.
- Output: `runs/<timestamp>-<recipe>/report.md` and `report.json`.
- It checks the agent credential, builds the sandbox, applies the network policy from the scope, starts the agent, collects evidence and writes the report.
