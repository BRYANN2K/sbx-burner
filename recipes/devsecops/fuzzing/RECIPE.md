---
name: fuzzing
category: devsecops
summary: Fuzz the user's C and Go harnesses for five minutes each, then deduplicate, minimise and classify every crash with its reproducer.
risk: low
time: 20m
tested_with: [codex]
variants:
  linux: beta
  macos: planned
status: beta
licence: Apache-2.0
sources:
  - https://go.dev/doc/security/fuzz/
  - https://github.com/AFLplusplus/AFLplusplus
  - https://llvm.org/docs/LibFuzzer.html
---

# fuzzing

The agent runs coverage-guided fuzzers against small parsers: clang with
libFuzzer or AFL++ on a C target, `go test -fuzz` on a Go target. Every
distinct crash is minimised to a reproducer, classified by its sanitizer
report or panic trace, and reported once. The crash input is the proof.

## When to use it

- To smoke-test a parser or codec before shipping it.
- To learn fuzzing triage: dedupe by stack, minimise, classify.
- On your own code with `--target ./my-parser` or `--target-repo`.

## What you get

- `report.md` and `report.json` in `runs/<timestamp>-fuzzing/`.
- One finding per unique crash, with the minimised input that reproduces it
  and the stack that classifies it.
- `artifacts/fuzz-stats.json`: executions and unique crashes per target.

## Run

```console
$ python -m lab run devsecops/fuzzing --target ./my-code   # your harness + source
$ python -m lab run devsecops/fuzzing --target-repo owner/my-parser@main  # a git repo
$ python -m lab run devsecops/fuzzing --target . --dry-run # preview the plan
```

`--target` mounts your code read-only at `/home/agent/target`.
`--target-repo SRC[@REF]` (`owner/repo`, an https or ssh URL) clones a
repository on the host with your own git login (private repositories work;
no credential enters the sandbox) and mounts it the same way. The agent
looks for fuzzing harnesses (`fuzz_*.c`, `Fuzz*` Go tests) or writes a small
one. With no target flag the run is refused. Each harness gets at
most five minutes of fuzzing.

## Evidence

| Artifact | Content |
| --- | --- |
| `artifacts/crash-<id>.bin` | Minimised input that reproduces the crash |
| `artifacts/<id>-stack.txt` | Sanitizer report or panic trace classifying it |
| `artifacts/fuzz-stats.json` | Executions, seconds and unique crashes per target |

## Safety

- Fuzzing runs inside the sandbox only: no network is needed after the tool
  installs, and the policy allows nothing while the agent runs.
- Five minutes per target, then the agent stops the fuzzer: no endless runs.
- A crash input is never executed outside the fuzzed binary.

## Variants

- Linux: Docker's built-in Debian agent; clang+libFuzzer, Go and AFL++ are
  installed by `tools/install.sh` from Debian packages.
- macOS: planned, through macsbx.

## Licences

| Tool | Licence | How it is used |
| --- | --- | --- |
| clang / libFuzzer (LLVM 19) | Apache-2.0 with LLVM exceptions | Debian package `clang`, `libclang-rt-dev` |
| Go | BSD-3-Clause | Debian package `golang` |
| AFL++ 4.21c | AGPL-3.0 | Debian package `afl++`, run only, never vendored |
