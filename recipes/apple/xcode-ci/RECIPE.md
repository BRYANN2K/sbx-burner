---
name: xcode-ci
category: apple
summary: Build, test and archive an Xcode project in a throwaway macOS VM, with signing through the host proxy.
risk: low
time: 30m
variants:
  linux: n/a
  macos: planned
status: planned
licence: Apache-2.0
sources:
  - https://github.com/getsentry/XcodeBuildMCP
  - https://github.com/cpisciotta/xcbeautify
  - macsbx (not yet published)
---

# xcode-ci

Build, test and archive an Xcode project in a throwaway macOS VM, with signing through the host proxy.

Status: **planned**. This recipe is macOS-only and arrives with
macsbx (not yet published), which runs macOS VMs for coding
agents. There is no Linux variant: the work needs macOS itself.

## What it will ship

The same contract as every recipe: `AGENTS.md`, skills, pinned tools,
`run.py`, a scope example and an eval that checks the evidence.

## Notes

- macOS images are built locally by scripts; none is shipped (Apple SLA).
- At most two macOS guests run on one Mac.
