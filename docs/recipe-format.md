# Recipe format

A recipe is a folder. The runner reads it, builds a sandbox, starts an agent and collects evidence.

## Layout

```
recipes/<category>/<name>/
├── RECIPE.md          # frontmatter: name, category, summary, risk (low|medium|high), time, tested_with (optional), variants, status, licence, sources
├── recipe.yaml        # variants: linux {kit, image, sbxenv}, macos {status: planned}
├── AGENTS.md          # role, scope rules, allowed tools, evidence format, stop conditions
├── scope.example.yaml # authorization, valid dates, targets, techniques (security recipes)
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
| `tested_with` | Optional. Agents proven by a real run, for example `[codex]`. Information only. |
| `variants` | `linux`, `macos`. |
| `status` | For example `planned`, `experimental`, `stable`. |
| `licence` | SPDX id of the recipe itself. |
| `sources` | Upstream projects and their licences. Anything vendored or inspired by. |

Any agent the runner lists can run a recipe on the standard base; recipes with their own base image need an agent with a mixin kit (claude, codex today). Devin sign-in is currently broken in sbx. `python -m lab agents` lists them (`burner agents` does the same). There is no `agents` field. An old `agents` key is ignored with a lint warning, so remove it.

Example:

```yaml
---
name: secrets-scan
category: devsecops
summary: Find committed secrets in a repository and its history.
risk: low
time: 10 min
tested_with: [codex]
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

## Target kinds

A recipe tests the user's own target. The sandbox is only the workbench. A recipe declares which kinds it accepts under `run` in `recipe.yaml`:

```yaml
run:
  target: required                 # required | optional | none
  targets: [path, repo, app, image, port, url, demo]
  demo: fixtures/demo.sh           # starts the bundled lab; runs only with --demo
  target_health: /                 # polled after --target-port starts the container
  network:
    install_allow: []              # demo image pull hosts go here too
```

| Key | Meaning |
|---|---|
| `run.target` | Whether some target is needed: `required`, `optional` or `none`. |
| `run.targets` | Accepted kinds, a subset of `path`, `repo`, `app`, `image`, `port`, `url`, `demo`. Default: `[path]` when `target` is not `none`, else `[]`. |
| `run.demo` | A script inside the recipe folder that starts the bundled lab in the sandbox. Required if `demo` is listed. |
| `run.target_health` | HTTP path polled after `--target-port` starts the user's container. Starts with `/`. Default `/`. |

The kinds and their flags:

| Kind | Flag | Meaning |
|---|---|---|
| `path` | `--target PATH` | The user's files, read-only at `/home/agent/target`. |
| `repo` | `--target-repo SRC[@REF]` | A git repo cloned on the host, mounted read-only at `/home/agent/target`. Options: `--with-submodules`, `--pr N`. |
| `app` | `--target-app PATH\|SRC[@REF]` | A project installed and started in the sandbox on `localhost`. Options: `--app-install`, `--app-cmd`, `--app-port`, `--app-health`, `--app-env`. |
| `image` | `--target-image REF\|TAR` | Scan or inspect an image. A registry ref or a `docker save` tarball. |
| `port` | `--target-image` with `--target-port N\|HOST:CONTAINER` | Run the user's image as an app on `localhost:HOST`. Requires `image`. |
| `url` | `--target-url URL` | An authorized remote `http` or `https` app. |
| `demo` | `--demo` | The bundled lab from `run.demo`. |

Training labs and `foundation/scope-guard` use `target: none`. Their subject is the lab or the policy.

### Refusals

The runner stops before it creates a sandbox when:

- the recipe has `target: required` and the run has no target and no `--demo`. The message lists the flags the recipe accepts;
- a flag names a kind the recipe does not list in `targets`;
- `--demo` is used and the recipe has no `run.demo`;
- `--demo` is combined with a user target. The only allowed combination is `--target PATH` as supporting input to `--target-image` or `--target-url`, when the recipe lists both kinds;
- `--target-port` is used without `--target-image`, or a port is outside 1 to 65535;
- `--pr` is used without `--target-repo`, or `--with-submodules` without `--target-repo` or `--target-app`;
- `--target-repo` is a URL with credentials, a `file://` or `ext::` URL, plain `http://`, or starts with `-`;
- `--target-app` has no detectable start command and no `--app-cmd` and `--app-port`, or its source holds a symlink that points outside the tree;
- `--app-env` names a file that does not exist;
- `--target-image TAR` names a file that is missing or is not a regular file;
- `--target-url` has no `--scope`, a host that is not in scope, a scheme other than `http` or `https`, or credentials in the URL.

### What the agent sees

`TASK.md` gets a `## Target` section. The agent step gets these environment variables. Only the ones that apply are set.

| Variable | Value |
|---|---|
| `LAB_TARGET_KIND` | `path`, `repo`, `app`, `image`, `url` or `demo`. |
| `LAB_TARGET_PATH` | `/home/agent/target`. Set for `path` and `repo`. |
| `LAB_TARGET_REPO` | The repo URL, without credentials. |
| `LAB_TARGET_BASE`, `LAB_TARGET_HEAD` | The base and head of the pull request, with `--pr`. |
| `LAB_TARGET_IMAGE` | The image ref, or `tarball:<file>`. |
| `LAB_TARGET_URL` | `http://localhost:HOST` for `--target-port`, `http://localhost:PORT` for an app, or the `--target-url`. |
| `LAB_DEMO` | `1` in demo mode. |

`AGENTS.md` or a skill must read each declared kind from its variable. `lab lint` fails when a declared kind is never mentioned. It looks for `LAB_TARGET_PATH` or `/home/agent/target` (`path`, `repo`), `LAB_TARGET_IMAGE` (`image`), `LAB_TARGET_URL` (`port`, `app`, `url`) and `LAB_DEMO` (`demo`).

Lint also rejects: an unknown kind, `port` without `image`, `demo` without a `run.demo` file, `target: none` with a non-empty `targets`, and a `target_health` that does not start with `/`.

### Target identity in the report

`report.json` holds `run.target`, and `report.md` shows the same facts. They say exactly what was tested.

| Kind | Recorded |
|---|---|
| `path` | `identity.sha256` and `identity.files`. A file gets its sha256. A directory gets a tree digest over the sorted lines `relative path NUL file sha256`, skipping `.git/`. Above 20 000 files the digest is `skipped: too many files`. A git work tree also gets `git_head` and `dirty`. |
| `repo` | The repo URL without credentials, the commit SHA, the ref, the pull request number and a tree digest. |
| `app` | The source identity (path digest, or repo URL and commit), the detected stack and the start command. For `--app-env`, the keys only, never the values. |
| `image` | The resolved image digest and its `source`: `local`, `registry`, `registry-sandbox` or `tarball`. Local builds and tarballs fall back to the image ID. |
| `port` | The image, the host and container ports, the URL, and `added_by_runner`. |
| `url` | The URL as given. |
| `demo` | The `run.demo` script path and its sha256. |

The path digest is computed on the host before the mount. It reads every file once, so a very large target takes time. Symlinks that point outside the tree are not read.

`report.json` also holds `run.operator_notes` and `run.asks`. See [Live runs](live-runs.md).

## Runner

```
python -m lab run <recipe> [--scope file] [--agent claude|codex]
    [--target PATH] [--target-repo SRC[@REF] [--with-submodules] [--pr N]]
    [--target-app PATH|SRC[@REF]] [--target-image REF|TAR [--target-port N|HOST:CONTAINER]]
    [--target-url URL] [--demo] [--prompt TEXT] [--prompt-file FILE]
    [--events FILE|-] [--on-ask MODE] [--dry-run]
```

- Python 3.11+, standard library only.
- Output: `runs/<timestamp>-<recipe>/report.md` and `report.json`.
- It checks the agent credential, builds the sandbox, applies the network policy from the scope, starts the agent, collects evidence and writes the report.
