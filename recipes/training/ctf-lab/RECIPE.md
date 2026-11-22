---
name: ctf-lab
category: training
summary: Build a three-challenge CTF with per-build random flags, verify each challenge is solvable and the checker works, then reset to a clean state.
risk: medium
time: 15m
agents: [claude, codex]
variants:
  linux: beta
  macos: planned
status: beta
licence: Apache-2.0
sources:
  - https://owasp.org/Top10/A01_2021-Broken_Access_Control/
  - https://cryptopals.com/sets/1/challenges/6
  - https://www.w3.org/TR/png/#11textinfo
---

# ctf-lab

The agent is the lab operator of a small capture-the-flag. It builds three
original challenges, proves that each one can be solved the intended way,
proves that the flag checker accepts the right flag and rejects a wrong one,
and returns the lab to a clean state.

| Challenge | Category | Idea |
| --- | --- | --- |
| `web-idor` | web | A notes API on `localhost:8081` never checks who owns a note |
| `crypto-xor` | crypto | Repeating-key XOR with a known message header |
| `forensics-meta` | forensics | A PNG carries the flag in a text chunk |

Flags are random for every build. They exist only in the build directory.

## When to use it

- Before a training session, to check the CTF is healthy.
- As the target of `training/ctf-solver`.
- As a template for adding your own small challenges.

## What you get

- `report.md` and `report.json` in `runs/<timestamp>-ctf-lab/`.
- A build log, one solvability check per challenge, a checker test and a
  reset proof.
- A finding only when something is broken: a challenge that cannot be solved,
  or a checker that accepts a wrong flag.

## Run

```console
$ cp recipes/training/ctf-lab/scope.example.yaml scope.yaml   # set owner and dates
$ python -m lab run training/ctf-lab --scope scope.yaml --dry-run
$ python -m lab run training/ctf-lab --scope scope.yaml
```

To play by hand, outside the runner:

```console
$ cd recipes/training/ctf-lab/fixtures
$ bash build.sh && bash serve.sh start      # handouts in ./ctf-build/handout/
$ bash check.sh web-idor 'flag{...}'
$ bash reset.sh
```

## Evidence

| Artifact | Content |
| --- | --- |
| `artifacts/build.log` | Output of `fixtures/build.sh` and `serve.sh start` |
| `artifacts/solve-<challenge>.txt` | Solve command and checker verdict, flag masked |
| `artifacts/checker-negative.txt` | The checker rejecting a wrong flag and an unknown challenge |
| `artifacts/solvable.jsonl` | One JSON line per challenge with its checker verdict |
| `artifacts/reset.txt` | Output of `fixtures/reset.sh` |

## Safety

- The only network service is the web challenge, bound to `127.0.0.1:8081`
  inside the sandbox.
- The challenges are benign: no exploit code, no malware, no real secret.
- Flags are generated at build time and are never stored in the repository.
  Evidence shows them masked.
- `reset.sh` deletes only a directory that `build.sh` created.
- The live flags sit in `ctf-build/.server/`. The rule that the agent must not
  read it exists only in the agent prompt — nothing technical blocks the read,
  so the eval proves solves went through the handouts, not the flag store.

## Variants

- Linux: `kalilinux/kali-rolling` through `kits/base-kali`, with
  `kits/lab-tools`. The lab itself needs only `bash`, `python3` and `curl`.
- macOS: planned, through macsbx.

## Licences

| Tool | Licence | How it is used |
| --- | --- | --- |
| Challenges under `fixtures/challenges/` | Apache-2.0 | Original to this repository |
| ExifTool | Artistic-1.0-Perl or GPL-1.0-or-later | Kali package, run only |
| xxd, file | Vim licence, BSD-2-Clause | Kali packages |
