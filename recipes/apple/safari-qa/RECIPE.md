---
name: safari-qa
category: apple
summary: Run web QA in real Safari through safaridriver in a macOS VM, with screenshots as evidence.
risk: low
time: 20m
agents: [claude, codex]
variants:
  linux: n/a
  macos: planned
status: planned
licence: Apache-2.0
sources:
  - https://developer.apple.com/documentation/webkit/testing-with-webdriver-in-safari
  - macsbx (not yet published)
---

# safari-qa

Run web QA in real Safari through safaridriver in a macOS VM, with screenshots as evidence.

Status: **planned**. This recipe is macOS-only and arrives with
macsbx (not yet published), which runs macOS VMs for coding
agents. There is no Linux variant: the work needs macOS itself.

## What it will ship

The same contract as every recipe: `AGENTS.md`, skills, pinned tools,
`run.py`, a scope example and an eval that checks the evidence.

## Notes

- macOS images are built locally by scripts; none is shipped (Apple SLA).
- At most two macOS guests run on one Mac.
