# Getting started

Run your first recipe: install `sbx`, store a credential, do a dry run, then a real run.

## Requirements

- `sbx` 0.45.0 or later. <!-- TODO(verify): the sbx docs say 0.45.0+ for their guides; confirm the minimum this repo needs. -->
- macOS 14+ on Apple silicon, Linux with KVM, or Windows 11. These are the `sbx` platform limits.
- Python 3.11+. No packages to install.
- A Docker account for `sbx login`.

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

Options:

| Option | Meaning |
|---|---|
| `--scope <file>` | Scope file. Required by security recipes. |
| `--agent claude\|codex` | Which agent to start. |
| `--dry-run` | Print the plan. Create nothing. |

The runner creates the sandbox, applies the policy, starts the agent, collects the output and writes the report. The sandbox is removed at the end unless the recipe says otherwise.

## 5. Read the result

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

## Next

- [Scope and safety](scope-and-safety.md)
- [Recipe format](recipe-format.md)
- [Writing a recipe](writing-a-recipe.md)
