# Getting started

Run your first recipe: install `sbx`, store a credential, do a dry run, then a real run.

## Requirements

- `sbx` 0.45.0 or later. <!-- TODO(verify): the sbx docs say 0.45.0+ for their guides; confirm the minimum this repo needs. -->
- macOS 14+ on Apple silicon, Linux with KVM, or Windows 11. These are the `sbx` platform limits.
- Python 3.11+. No packages to install.
- A Docker account for `sbx login`.
- A coding agent. Supported agents: Claude Code, Codex, Devin, Cursor, GitHub Copilot and OpenCode. `--agent` accepts `claude` and `codex` today.

## 1. Install sbx

macOS:

```sh
brew trust docker/tap
brew install docker/tap/sbx
sbx login
```

Linux (Ubuntu):

```sh
curl -fsSL https://get.docker.com | sudo SBX=1 sh
sbx login
```

Windows: `winget install -h Docker.sbx`.

Source: <https://docs.docker.com/ai/sandboxes/install/>.

## 2. Store an agent credential

Credentials live on the host. A proxy injects them into requests. The VM never sees the real value.

```sh
sbx secret set anthropic          # Claude Code, API key
sbx secret set openai --oauth     # Codex, ChatGPT login
sbx secret set openai             # Codex, API key
```

Claude Code can also log in from inside the sandbox with `/login`. That is interactive. Unattended runs need a stored host credential.

The runner checks for a credential before it creates a sandbox. If one is missing, it prints the command above and stops. It never asks for a key.

Source: <https://docs.docker.com/ai/sandboxes/security/credentials/>.

## 3. Clone and dry-run

```sh
git clone https://github.com/BRYANN2K/agent-lab-sbx.git
cd agent-lab-sbx
python -m lab run training/vuln-lab --dry-run
```

The dry run changes nothing. It prints:

- the recipe variant it picked (Linux),
- the sandbox name and image,
- the network policy rules it would apply,
- the agent and its starting prompt,
- the output directory.

## 4. Run a recipe

```sh
python -m lab run training/vuln-lab --agent claude
```

A recipe that tests something of yours needs a target. Your first run can use `--demo`, which tests the recipe's own bundled lab:

```sh
python -m lab run pentest/web-recon --scope scope.yaml --demo
```

Options:

| Option | Meaning |
|---|---|
| `--scope <file>` | Scope file. Required by security recipes. |
| `--agent claude\|codex` | Which agent to start. |
| `--target`, `--target-repo`, `--target-app`, `--target-image`, `--target-port`, `--target-url`, `--demo` | What to test. See [Choose your target](#5-choose-your-target). |
| `--dry-run` | Print the plan. Create nothing. |

The runner creates the sandbox, applies the policy, starts the agent, collects the output and writes the report. The sandbox is removed at the end unless the recipe says otherwise.

A single CLI named `burner` (product name sbx-burner) is the front end for the same runner. See [burner](#burner). This page uses `python -m lab`.

## 5. Choose your target

A recipe tests **your** target: your repository or files, your project, your Docker image, your running app, or a remote URL you are authorized to test. The sandbox is only the isolated workbench.

Bundled lab targets (Juice Shop, sample binaries, planted logs) run only with `--demo`. Two exceptions: the training labs (`training/vuln-lab`, `training/ctf-lab`) and `foundation/scope-guard`. Their subject is the lab or the policy, so they need no target.

Each recipe lists the kinds it accepts in its `RECIPE.md` and in `run.targets` of its `recipe.yaml`. A recipe that needs a target refuses to run without one and prints the flags it accepts.

One rule for every source: **your credentials stay on your machine.** The runner clones repos and pulls images on the host with your own logins. The sandbox only receives the result.

### Your files: `--target`

```sh
python -m lab run devsecops/secrets-scan --target ~/code/my-repo
```

The directory is mounted **read-only** at `/home/agent/target`. A leading `~` is expanded by the runner.

Point `--target` at the directory that matters. Before the mount, the runner reads every file once to record a digest, so a very large target (many GB) takes time. There is no size cap beyond a file-count cap (20 000 files). Symlinks that point outside the tree are not read.

### Your repository: `--target-repo`

```sh
python -m lab run devsecops/secrets-scan --target-repo owner/repo@v1.2
python -m lab run devsecops/pr-security-review --target-repo owner/repo --pr 42
```

Accepted sources: `owner/repo` (GitHub), an `https://` URL, or an ssh URL such as `git@host:owner/repo.git`. `@REF` picks a branch, tag or commit. Without it you get the default branch.

- The runner clones on the host with your git login (`gh auth`, ssh-agent or a credential helper). Full history is kept. It never prompts. A missing credential fails fast.
- Add `--with-submodules` to clone submodules too.
- `--pr N` checks out pull request N. The agent gets the base and head in `LAB_TARGET_BASE` and `LAB_TARGET_HEAD`.
- The clone is mounted read-only at `/home/agent/target`, like `--target`. Credentials are scrubbed from its `.git/config` first. It is deleted when the run ends.
- A URL that carries credentials (`user:token@`), `file://`, `ext::` and plain `http://` are refused. For a local folder use `--target`.

The report records the repo URL (without credentials), the commit SHA, the ref and a tree digest.

### Your project, started in the sandbox: `--target-app`

```sh
python -m lab run pentest/web-recon --scope scope.yaml --target-app ~/code/my-app
python -m lab run pentest/web-recon --scope scope.yaml --target-app owner/repo@main
```

The source is a local folder or a repo (cloned like `--target-repo`). Your folder is never modified: the runner copies it into the sandbox workspace. Symlinks that point outside the tree are refused.

The runner detects the stack from your files and shows it in the plan. It supports npm, pnpm and yarn, Python (uvicorn, gunicorn, Flask, Django, FastAPI), Go, Rails, Composer (PHP, Laravel) and Cargo. If it cannot find a start command, it refuses and names the flags to use.

| Flag | Meaning |
|---|---|
| `--app-install CMD` | Replace the detected install command. |
| `--app-cmd CMD` | Replace the detected start command. |
| `--app-port N` | Replace the detected port. |
| `--app-health PATH` | HTTP path polled until the app answers. Default `/`. |
| `--app-env FILE` | A dotenv file copied to `app/.env`. |

Three things to know:

- Dependencies install inside the sandbox during the install window. The registry hosts for the ecosystem are open only then and closed before the agent starts. **Lifecycle scripts** (npm `postinstall` and similar) run inside the sandbox, never on your machine.
- `--app-install` and `--app-cmd` also run only inside the sandbox.
- `--app-env` values are never logged and are redacted from logs, evidence and reports. The same holds for your project's own `.env`, which is copied with the app when you give no `--app-env`. Real production secrets do not belong in either file.

The app runs on `localhost:PORT`. The runner adds that host to the in-memory scope, marked "added by runner". The agent reads it from `LAB_TARGET_URL`.

### Your image: `--target-image`

```sh
python -m lab run devsecops/container-scan --target-image me/app:1.2
python -m lab run devsecops/container-scan --target-image ./app.tar
```

For a reference, the runner looks for the image in this order:

1. **Your local Docker daemon.** `docker save` on the host. Nothing is pulled.
2. **A registry, pulled on the host** with your `docker login`. This covers private registries.
3. **A pull inside the sandbox**, only when the host has no Docker and the registry is public (Docker Hub, `ghcr.io`). Its registry hosts are open only during the install window. A private reference is refused in this case.

The image is then loaded inside the sandbox. Registry credentials never enter the sandbox.

For a tarball made with `docker save`, the runner stages it in the run directory and mounts only that folder read-only. On the same filesystem the stage is a hardlink (same inode, nothing copied). Otherwise it is a copy. Other files next to your tarball are not exposed.

The runner records the image digest and where it came from: `local`, `registry`, `registry-sandbox` or `tarball`. The saved tarball is deleted at the end of the run.

### Your running app, from an image: `--target-port`

The runner starts your image as container `lab-target` on `127.0.0.1` and waits for it to answer. Use `N` or `HOST:CONTAINER`.

```sh
python -m lab run pentest/web-recon --scope scope.yaml \
    --target-image me/app:1.2 --target-port 8080:3000
```

The runner adds `localhost:8080` to the in-memory scope, marked "added by runner". It never rewrites your scope file. Your container shares the sandbox network policy. See [Scope and safety](scope-and-safety.md).

### A remote app: `--target-url`

```sh
python -m lab run pentest/bug-bounty --scope scope.yaml \
    --target-url https://app.example.com
```

The URL must be `http` or `https` and its host must already be in the scope file. The runner never adds it. A URL with credentials is refused. Store credentials with `sbx secret`.

```yaml
# scope.yaml (excerpt)
authorization:
  type: written
  reference: https://example.com/security   # the program policy or signed letter
targets:
  - name: app
    hosts: [app.example.com]
```

A public host needs `authorization.type: written` with a `reference`.

### The bundled lab: `--demo`

```sh
python -m lab run pentest/web-recon --scope scope.yaml --demo
```

`--demo` cannot be combined with your own target.

### Supporting files

When a recipe accepts both kinds, add `--target PATH` to an image, URL or app target. For example, an OpenAPI schema for `pentest/api-greybox`.

## 6. Steer and watch a run

You can add notes for the agent, stream what it does, and answer its questions. See [Live runs](live-runs.md).

## 7. Read the result

```
runs/<timestamp>-<recipe>/
├── report.md     # human report
└── report.json   # same data, machine readable
```

`runs/` is git-ignored. See [Evidence and reports](evidence-and-reports.md).

## Useful sbx commands

```sh
sbx ls                       # list sandboxes
sbx stop <name>              # pause
sbx rm <name>                # delete
sbx run --rm claude          # throwaway session, removed on exit
sbx policy ls                # show network rules
sbx policy allow network <host>
```

If the runner stops half way, `sbx ls` shows what is left. Remove it with `sbx rm`.

## burner

`burner` is a single binary (product name sbx-burner). It wraps the same runner and takes the same target flags. Run `burner` with no arguments for an interactive menu.

```text
burner                      interactive menu
burner list [--json]        recipes in the catalog and in ~/.burner/recipes
burner show <recipe> [--json]
burner run <recipe> [flags] run a recipe
burner new <category>/<name>
burner lint [recipe...]     check recipes against the contract
burner eval [recipe]        check a recipe produces its evidence
burner scope <file> [--host H]
burner doctor [--json]
burner answer <run-dir> <ask-id> <answer>
burner update [--check] [--install]
burner catalog add <git-url> [--name N] | list
burner mcp                  MCP server on stdio
burner version
```

`burner run` also takes `--yes` (never prompt, fail with exit 3 when something is missing) and `--json` (events as NDJSON on stdout). Exit codes: 0 ok, 1 internal error, 2 usage or refused, 3 not ready, 4 run failed, 5 evidence gate failed. Run `burner --help` for the full list.

## Next

- [Live runs](live-runs.md)

- [Scope and safety](scope-and-safety.md)
- [Recipe format](recipe-format.md)
- [Writing a recipe](writing-a-recipe.md)
