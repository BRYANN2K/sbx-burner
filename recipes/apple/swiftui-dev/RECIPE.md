---
name: swiftui-dev
category: apple
summary: SwiftUI coding agent with build, simulator run and screenshot feedback in a macOS VM.
risk: low
time: 30m
agents: [claude, codex]
variants:
  linux: n/a
  macos: planned
status: planned
licence: Apache-2.0
sources:
  - https://developer.apple.com/documentation/swiftui
  - macsbx (not yet published)
---

# swiftui-dev

SwiftUI coding agent with build, simulator run and screenshot feedback in a macOS VM.

Status: **planned**. This recipe is macOS-only and arrives with
macsbx (not yet published), which runs macOS VMs for coding
agents. There is no Linux variant: the work needs macOS itself.

## What it will ship

The same contract as every recipe: `AGENTS.md`, skills, pinned tools,
`run.py`, a scope example and an eval that checks the evidence.

## Notes

- macOS images are built locally by scripts; none is shipped (Apple SLA).
- At most two macOS guests run on one Mac.
