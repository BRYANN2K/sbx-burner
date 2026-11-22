<div align="center">

<img src="assets/banner.png" alt="sbx-burner. A row of disposable lab boxes, each holding a small terminal, labelled pentest, malware, detection and DevSecOps." width="100%">

**Disposable lab recipes for coding agents, run inside Docker Sandboxes.**

Pick a recipe, give it a scope, let the agent work in a throwaway VM, and get a report with proof.

[Quick start](#quick-start) · [Gallery](#gallery) · [Recipe format](docs/recipe-format.md) · [Write a recipe](docs/writing-a-recipe.md) · [Scope and safety](docs/scope-and-safety.md) · [Roadmap](docs/roadmap.md)

</div>

---

## Why

Skill packs give agents knowledge. They usually run on your host, and the scope is a sentence in a prompt.

sbx-burner adds the missing parts around the agent:

- **A disposable VM.** Each recipe runs in a Docker Sandbox (`sbx`). Destroy it when the run ends.
- **Scope enforced by the network.** Security recipes need a scope file. The sandbox network policy blocks hosts outside it. A prompt is not the only guard.
- **A runner.** One command creates the sandbox, starts the agent, collects the output and writes the report.
- **Evidence.** A finding needs proof: a command, its output, a request, a file. No proof, no finding.

Use cases: pentest (white, grey and black box), bug bounty, malware triage, detection engineering, hardening audits, DevSecOps (secrets, SAST, SCA, SBOM, signing).

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

Install burner, the menu and CLI around the runner (macOS and Linux). The script verifies the release signature and checksum:

```sh
curl -fsSL https://raw.githubusercontent.com/BRYANN2K/sbx-burner/main/install.sh | sh
burner setup
```

A pinned version, Homebrew (planned) and manual download with `cosign verify-blob`: [Install](docs/install.md).

Store a credential for your agent. It stays on the host. The sandbox only sees a placeholder.

```sh
sbx secret set anthropic        # Claude Code
sbx secret set openai --oauth   # Codex
```

Clone the repo and check a recipe without creating a sandbox:

```sh
git clone https://github.com/BRYANN2K/sbx-burner.git
cd sbx-burner
python -m lab run devsecops/secrets-scan --target . --dry-run
```

`--dry-run` prints what the runner would do: the sandbox, the network policy, the agent and the output paths. Remove the flag to run it. Results land in `runs/<timestamp>-<recipe>/report.md` and `report.json`.

More in [Getting started](docs/getting-started.md).

## Gallery

<!-- recipes:start -->
27 recipes. Generated from `recipes.yaml` by `scripts/gen_index.py`; do not edit by hand.

| Recipe | Category | Summary | Risk | Linux | macOS |
| --- | --- | --- | --- | --- | --- |
| [api-greybox](recipes/pentest/api-greybox/RECIPE.md) | pentest | Grey-box API test with a schema and two test users; proves broken authorization (BOLA, BFLA, mass assignment) with request pairs. | high | beta | planned |
| [binary-blackbox](recipes/pentest/binary-blackbox/RECIPE.md) | pentest | Black-box analysis of a Linux binary — static triage, radare2 hypotheses, and dynamic proof of each behaviour with a crafted input. | medium | beta | planned |
| [bug-bounty](recipes/pentest/bug-bounty/RECIPE.md) | pentest | Authorized bug-bounty testing of one program — distill the rules, bounded recon and manual checks, minimal proof, one platform-neutral report per finding. | high | beta | planned |
| [dast-light](recipes/pentest/dast-light/RECIPE.md) | pentest | Passive OWASP ZAP baseline scan of a local web app, then triage; each kept alert is deduplicated and confirmed with one manual request. | medium | beta | planned |
| [web-recon](recipes/pentest/web-recon/RECIPE.md) | pentest | Map the attack surface of in-scope web hosts with httpx, ffuf and low-severity nuclei templates, and write it to artifacts/surface.json. | medium | beta | planned |
| [webapp-blackbox](recipes/pentest/webapp-blackbox/RECIPE.md) | pentest | Black-box test of an in-scope web app — map, then auth, session, access control, injection and business logic; one minimal PoC per finding. | high | beta | planned |
| [whitebox-review](recipes/pentest/whitebox-review/RECIPE.md) | pentest | Source review with reachability; each finding has a source-to-sink trace, a concrete input, a local confirmation when possible, and a fix diff. | medium | beta | planned |
| [container-scan](recipes/devsecops/container-scan/RECIPE.md) | devsecops | Scan the user's container image — a Dockerfile context or an image ref/tarball — with trivy and grype, then reconcile and rank fixes. | low | beta | planned |
| [fuzzing](recipes/devsecops/fuzzing/RECIPE.md) | devsecops | Fuzz the user's C and Go harnesses for five minutes each, then deduplicate, minimise and classify every crash with its reproducer. | low | beta | planned |
| [gate](recipes/devsecops/gate/RECIPE.md) | devsecops | Run secrets, SCA, SAST, IaC and licence checks on a codebase, merge every report into one SARIF and decide pass or fail from a read-only policy file. | low | beta | planned |
| [iac-scan](recipes/devsecops/iac-scan/RECIPE.md) | devsecops | Scan Terraform, Kubernetes manifests and Dockerfiles for misconfigurations with trivy, then split real exposure from hygiene. | low | beta | planned |
| [license-compliance](recipes/devsecops/license-compliance/RECIPE.md) | devsecops | Build an SBOM with syft and check every component licence against an allow / review / deny policy file. | low | beta | planned |
| [pr-security-review](recipes/devsecops/pr-security-review/RECIPE.md) | devsecops | Review a pull request diff for security issues; report only findings with the vulnerable line, an exploit scenario and the diff hunk. | low | beta | planned |
| [sast-semgrep](recipes/devsecops/sast-semgrep/RECIPE.md) | devsecops | Static-analyse a codebase with semgrep and a small set of bundled original rules, confirming every hit against the code before reporting. | low | beta | planned |
| [sbom-sign](recipes/devsecops/sbom-sign/RECIPE.md) | devsecops | Build CycloneDX and SPDX SBOMs of a project with syft, sign the CycloneDX document with a throwaway cosign key pair, and verify the signature offline. | low | beta | planned |
| [sca-osv](recipes/devsecops/sca-osv/RECIPE.md) | devsecops | Scan a project's lockfiles and manifests for known dependency vulnerabilities with osv-scanner, then report one finding per advisory group. | low | beta | planned |
| [secrets-scan](recipes/devsecops/secrets-scan/RECIPE.md) | devsecops | Scan a repository and its git history for leaked credentials with gitleaks, then triage every hit before reporting. | low | beta | planned |
| [supply-chain-risk](recipes/devsecops/supply-chain-risk/RECIPE.md) | devsecops | Assess a project's third-party dependencies for supply-chain risk: install scripts, floating versions, look-alike names, registry health and OpenSSF Scorecard. | low | beta | planned |
| [ios-app-audit](recipes/apple/ios-app-audit/RECIPE.md) | apple | Audit an iOS app you own: entitlements, privacy manifest, transport security, storage and dependency risks. | medium | n/a | planned |
| [macho-triage](recipes/apple/macho-triage/RECIPE.md) | apple | Static triage of a Mach-O sample: signature, entitlements, capabilities and YARA matches, offline. | high | n/a | planned |
| [macos-es-detections](recipes/apple/macos-es-detections/RECIPE.md) | apple | Replay ATT&CK tests on macOS and check Endpoint Security events against expected detections. | medium | n/a | planned |
| [macos-malware-dynamic](recipes/apple/macos-malware-dynamic/RECIPE.md) | apple | Detonate a macOS sample offline in a SIP-off VM, capture ES events and persistence changes, then destroy the VM. | high | n/a | planned |
| [macos-mscp-audit](recipes/apple/macos-mscp-audit/RECIPE.md) | apple | Audit a macOS VM against an mSCP baseline (CIS or NIST) and report pass or fail per rule. | low | n/a | planned |
| [notarize-sign](recipes/apple/notarize-sign/RECIPE.md) | apple | Sign and notarize a macOS app in a clean VM, with credentials injected by the host proxy only. | medium | n/a | planned |
| [safari-qa](recipes/apple/safari-qa/RECIPE.md) | apple | Run web QA in real Safari through safaridriver in a macOS VM, with screenshots as evidence. | low | n/a | planned |
| [swiftui-dev](recipes/apple/swiftui-dev/RECIPE.md) | apple | SwiftUI coding agent with build, simulator run and screenshot feedback in a macOS VM. | low | n/a | planned |
| [xcode-ci](recipes/apple/xcode-ci/RECIPE.md) | apple | Build, test and archive an Xcode project in a throwaway macOS VM, with signing through the host proxy. | low | n/a | planned |
<!-- recipes:end -->

Categories and build order are in the [roadmap](docs/roadmap.md).

## Safety

- Every security recipe needs a [scope file](docs/scope-and-safety.md): authorization, valid dates, targets, techniques.
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
