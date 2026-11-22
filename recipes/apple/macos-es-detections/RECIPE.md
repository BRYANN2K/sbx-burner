---
name: macos-es-detections
category: apple
summary: Replay ATT&CK tests on macOS and check Endpoint Security events against expected detections.
risk: medium
time: 45m
variants:
  linux: n/a
  macos: planned
status: planned
licence: Apache-2.0
sources:
  - https://github.com/redcanaryco/atomic-red-team
  - https://developer.apple.com/documentation/endpointsecurity
  - macsbx (not yet published)
---

# macos-es-detections

Replay ATT&CK tests on macOS and check Endpoint Security events against expected detections.

Status: **planned**. This recipe is macOS-only and arrives with
macsbx (not yet published), which runs macOS VMs for coding
agents. There is no Linux variant: the work needs macOS itself.

## What it will ship

The same contract as every recipe: `AGENTS.md`, skills, pinned tools,
`run.py`, a scope example (required to run) and an eval that checks the evidence.

## Notes

- macOS images are built locally by scripts; none is shipped (Apple SLA).
- At most two macOS guests run on one Mac.
