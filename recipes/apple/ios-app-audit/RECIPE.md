---
name: ios-app-audit
category: apple
summary: Audit an iOS app you own: entitlements, privacy manifest, transport security, storage and dependency risks.
risk: medium
time: 60m
agents: [claude, codex]
variants:
  linux: n/a
  macos: planned
status: planned
licence: Apache-2.0
sources:
  - https://github.com/blacktop/ipsw
  - https://mas.owasp.org/
  - macsbx (not yet published)
---

# ios-app-audit

Audit an iOS app you own: entitlements, privacy manifest, transport security, storage and dependency risks.

Status: **planned**. This recipe is macOS-only and arrives with
macsbx (not yet published), which runs macOS VMs for coding
agents. There is no Linux variant: the work needs macOS itself.

## What it will ship

The same contract as every recipe: `AGENTS.md`, skills, pinned tools,
`run.py`, a scope example (required to run) and an eval that checks the evidence.

## Notes

- macOS images are built locally by scripts; none is shipped (Apple SLA).
- At most two macOS guests run on one Mac.
