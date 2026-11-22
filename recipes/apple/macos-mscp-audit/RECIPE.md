---
name: macos-mscp-audit
category: apple
summary: Audit a macOS VM against an mSCP baseline (CIS or NIST) and report pass or fail per rule.
risk: low
time: 30m
agents: [claude, codex]
variants:
  linux: n/a
  macos: planned
status: planned
licence: Apache-2.0
sources:
  - https://github.com/usnistgov/macos_security
  - macsbx (not yet published)
---

# macos-mscp-audit

Audit a macOS VM against an mSCP baseline (CIS or NIST) and report pass or fail per rule.

Status: **planned**. This recipe is macOS-only and arrives with
macsbx (not yet published), which runs macOS VMs for coding
agents. There is no Linux variant: the work needs macOS itself.

## What it will ship

The same contract as every recipe: `AGENTS.md`, skills, pinned tools,
`run.py`, a scope example (required to run) and an eval that checks the evidence.

## Notes

- macOS images are built locally by scripts; none is shipped (Apple SLA).
- At most two macOS guests run on one Mac.
