---
name: notarize-sign
category: apple
summary: Sign and notarize a macOS app in a clean VM, with credentials injected by the host proxy only.
risk: medium
time: 30m
variants:
  linux: n/a
  macos: planned
status: planned
licence: Apache-2.0
sources:
  - https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution
  - macsbx (not yet published)
---

# notarize-sign

Sign and notarize a macOS app in a clean VM, with credentials injected by the host proxy only.

Status: **planned**. This recipe is macOS-only and arrives with
macsbx (not yet published), which runs macOS VMs for coding
agents. There is no Linux variant: the work needs macOS itself.

## What it will ship

The same contract as every recipe: `AGENTS.md`, skills, pinned tools,
`run.py`, a scope example (required to run) and an eval that checks the evidence.

## Notes

- macOS images are built locally by scripts; none is shipped (Apple SLA).
- At most two macOS guests run on one Mac.
