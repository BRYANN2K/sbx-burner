# Roadmap

Linux now, macOS with macsbx.

## Platforms

- **Linux variant.** Every recipe has one. It runs in a stock `sbx` sandbox on a Linux image. This is built first.
- **macOS variant.** Arrives with [macsbx](https://github.com/BRYANN2K/macsbx), which runs macOS VMs behind the same project file. Until then each recipe lists `macos: status: planned` in `recipe.yaml`.
- **macOS-only recipes.** Listed under `apple`. They exist as stubs now: `RECIPE.md` and `recipe.yaml` only.

## Categories

| Category | Scope |
|---|---|
| `devsecops` | Secrets, SCA, SAST, SBOM, signing, containers, IaC, licences, fuzzing, CI gate. |
| `pentest` | Web, API, white, grey and black box, bug bounty. |
| `malware` | Static and offline dynamic triage, pcap analysis. |
| `detection` | Sigma, YARA, attack replay, detection CI. |
| `hardening` | CIS audits, container and Kubernetes, cloud, agent configuration. |
| `ir` | Linux forensics, log triage. |
| `ai-security` | LLM red team, MCP server audit. |
| `dev` | Plain coding agent in a sandbox. |
| `ci` | Ephemeral runners. |
| `web` | Cross-browser QA. |
| `cu` | Computer use on a virtual desktop. |
| `apple` | macOS-only. Planned. |

## Waves

About 45 recipes, built in four waves. One pull request per recipe. A wave finishes before the next starts. Each recipe needs a working eval.

### Wave 1: DevSecOps

No live targets.

- `devsecops/secrets-scan`, `sca-osv`, `sast-semgrep`, `sbom-sign`, `container-scan`, `iac-scan`, `license-compliance`, `pr-security-review`, `supply-chain-risk`, `fuzzing`, `gate`

### Wave 2: pentest

Against targets you own or are authorized to test.

- `pentest/web-recon`, `webapp-blackbox`, `api-greybox`, `whitebox-review`, `dast-light`, `binary-blackbox`, `bug-bounty`

### Wave 3: malware, detection, hardening, IR

- `malware/elf-pe-triage`, `linux-dynamic`, `pcap-analysis`
- `detection/sigma-author`, `yara-author`, `atomic-replay`, `detection-ci`
- `hardening/linux-cis-audit`, `container-k8s`, `cloud-audit`, `agent-config-audit`
- `ir/linux-forensics`, `log-triage`

### Wave 4: AI, dev, CI, computer use

- `ai-security/llm-redteam`, `mcp-server-audit`
- `dev/agent-dev`
- `ci/ephemeral-runner`
- `web/cross-browser-qa`
- `cu/desktop-qa`

### macOS-only, planned

Stubs only until macsbx can run them: `apple/xcode-ci`, `swiftui-dev`, `ios-app-audit`, `macho-triage`, `macos-malware-dynamic`, `macos-es-detections`, `macos-mscp-audit`, `safari-qa`, `notarize-sign`.

## Linux images

| Use | Image |
|---|---|
| Pentest, bug bounty | Kali |
| Malware | REMnux |
| Hardening, detection, IR, computer use | Ubuntu LTS |
| DevSecOps, dev, CI | Debian slim |

Each image must meet the `sbx` kit floor (bash, uid 1000 `agent`, git, CA store), or the kit adds what is missing. <!-- TODO(verify): confirm tags, sizes and kit platform floor for each image. -->

## Beyond the waves

- Release: public repository, gallery index, demo recording, launch notes.
- Packaging for Claude Code and Codex skill marketplaces.
- macOS variants through macsbx.

Dates are not promised. Waves ship when their evals pass.
