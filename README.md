<div align="center">

<img src="assets/banner.png" alt="agent-lab-sbx. A row of disposable lab boxes, each holding a small terminal, labelled pentest, malware, detection and DevSecOps." width="100%">

**Disposable lab recipes for coding agents, run inside Docker Sandboxes.**

Pick a recipe, give it a scope, let the agent work in a throwaway VM, and get a report with proof.

[Quick start](#quick-start) · [Gallery](#gallery) · [Recipe format](docs/recipe-format.md) · [Write a recipe](docs/writing-a-recipe.md) · [Scope and safety](docs/scope-and-safety.md) · [Roadmap](docs/roadmap.md)

</div>

---

## Why

Skill packs give agents knowledge. They usually run on your host, and the scope is a sentence in a prompt.

agent-lab-sbx adds the missing parts around the agent:

- **A disposable VM.** Each recipe runs in a Docker Sandbox (`sbx`). Destroy it when the run ends.
- **Scope enforced by the network.** Security recipes need a scope file. The sandbox network policy blocks hosts outside it. A prompt is not the only guard.
- **A runner.** One command creates the sandbox, starts the agent, collects the output and writes the report.
- **Evidence.** A finding needs proof: a command, its output, a request, a file. No proof, no finding.

Use cases: pentest (white, grey and black box), bug bounty, malware triage, detection engineering, hardening audits, CTF and training, DevSecOps (secrets, SAST, SCA, SBOM, signing).

This project is for defensive work and authorized testing only. See [Safety](#safety).

**Status.** Pre-release. The docs and the recipe contract are written. The runner and the recipes are being built in four waves. See the [roadmap](docs/roadmap.md).

## Quick start

You need:

- macOS 14+ on Apple silicon, Linux, or Windows 11 (the platforms `sbx` supports).
- Python 3.11 or later. The runner uses the standard library only.
- An agent credential stored on the host (Claude Code or Codex).

Install `sbx` and sign in. On macOS:

```sh
brew trust docker/tap
brew install docker/tap/sbx
sbx login
```

Other platforms: see the [sbx install page](https://docs.docker.com/ai/sandboxes/install/).

Store a credential for your agent. It stays on the host. The sandbox only sees a placeholder.

```sh
sbx secret set anthropic        # Claude Code
sbx secret set openai --oauth   # Codex
```

Clone the repo and check a recipe without creating a sandbox:

```sh
git clone https://github.com/BRYANN2K/agent-lab-sbx.git
cd agent-lab-sbx
python -m lab run training/vuln-lab --dry-run
```

`--dry-run` prints what the runner would do: the sandbox, the network policy, the agent and the output paths. Remove the flag to run it. Results land in `runs/<timestamp>-<recipe>/report.md` and `report.json`.

More in [Getting started](docs/getting-started.md).

## Gallery

<!-- recipes:start -->
| Recipe | Category | Summary | Risk | Status |
|---|---|---|---|---|
| _The table is generated from the recipes. No recipe is listed yet._ | | | | |
<!-- recipes:end -->

Categories and build order are in the [roadmap](docs/roadmap.md).

## Safety

- Every security recipe needs a [scope file](docs/scope-and-safety.md): targets, hosts, allowed techniques, dates.
- The runner turns the scope into `sbx` network policy. Hosts outside the scope are blocked.
- Targets are labs you start yourself, unless your scope file cites written authorization.
- Findings need [proof](docs/evidence-and-reports.md). Unproven leads go in a separate hypotheses list.
- No live malware in this repository.

Read [SECURITY.md](SECURITY.md) for the acceptable-use rules and how to report a vulnerability.

## Roadmap

Linux now, macOS with [macsbx](https://github.com/BRYANN2K/macsbx). Every recipe has a Linux variant first. The macOS variants come later, and some recipes are macOS-only. See [docs/roadmap.md](docs/roadmap.md).

## Contributing

New recipes, better rules and skills, new evals and fixes are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first. Commits use Conventional Commits and a DCO sign-off.

## Licence

[Apache-2.0](LICENSE). Vendored third-party material keeps its own licence and is credited in `NOTICE`.
