---
name: macho-triage
category: apple
summary: Static triage of a Mach-O sample: signature, entitlements, capabilities and YARA matches, offline.
risk: high
time: 20m
variants:
  linux: n/a
  macos: planned
status: planned
licence: Apache-2.0
sources:
  - https://github.com/blacktop/ipsw
  - https://github.com/mandiant/capa
  - https://github.com/VirusTotal/yara-x
  - macsbx (not yet published)
---

# macho-triage

Static triage of a Mach-O sample: signature, entitlements, capabilities and YARA matches, offline.

Status: **planned**. This recipe is macOS-only and arrives with
macsbx (not yet published), which runs macOS VMs for coding
agents. There is no Linux variant yet: it is planned for macsbx.

## What it will ship

The same contract as every recipe: `AGENTS.md`, skills, pinned tools,
`run.py`, a scope example (required to run) and an eval that checks the evidence.

## Notes

- macOS images are built locally by scripts; none is shipped (Apple SLA).
- At most two macOS guests run on one Mac.
