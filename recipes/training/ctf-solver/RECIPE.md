---
name: ctf-solver
category: training
summary: Solve CTF challenges from a target directory or on scope hosts, one finding per solved challenge with a solve script and the checker's verdict.
risk: medium
time: 30m
agents: [claude, codex]
variants:
  linux: beta
  macos: planned
status: beta
licence: Apache-2.0
sources:
  - https://github.com/ljagiello/ctf-skills
  - https://ctf101.org/
---

# ctf-solver

The agent solves capture-the-flag challenges. Challenges are files in the
read-only target, services on hosts listed in the scope, or both. Each solved
challenge becomes one finding whose proof is a small solve script and the
checker's answer. Each unsolved challenge becomes a hypothesis with the best
lead and the next step.

The bundled demo is a copy of the `training/ctf-lab` challenges shipped in
this recipe's `fixtures/`; `--demo` builds and starts it. For real work,
`--target` mounts your own challenge handouts — including that recipe's
`fixtures/` if you check out both.

## When to use it

- To practise a method per category: web, crypto, forensics, reversing and
  simple binary exploitation ("pwn-lite").
- To measure an agent on a known set of challenges with a checker.
- On a CTF event you take part in, with the event's hosts in a `written`
  scope and its rules as the reference.

## What you get

- `report.md` and `report.json` in `runs/<timestamp>-ctf-solver/`.
- One finding per solved challenge: category, weakness (CWE), solve script,
  checker output. Flags are masked.
- One hypothesis per unsolved challenge.

## Run

```console
$ cp recipes/training/ctf-solver/scope.example.yaml scope.yaml   # set owner and dates
$ python -m lab run training/ctf-solver --scope scope.yaml --demo      # bundled ctf-lab
$ python -m lab run training/ctf-solver --scope scope.yaml \
    --target ./my-challenges                                          # your own handouts
$ python -m lab run training/ctf-solver --scope scope.yaml \
    --target-url https://chall.example-ctf.org:31337                  # an in-scope challenge URL
$ python -m lab run training/ctf-solver --scope scope.yaml \
    --target ./my-challenges --dry-run                                # preview the plan
```

With `--demo` the runner builds the bundled lab into `ctf-build/` and
starts the web challenge on `localhost:8081`; the agent solves from
`ctf-build/handout/`, checks each flag with `fixtures/check.sh`, and
resets. With `--target` the handouts mount read-only at
`/home/agent/target`; a directory that ships `build.sh`/`check.sh` is
built the same way, other directories are read as challenge files. With
neither flag the run is refused.

With `--target-url` the agent works only against that URL and the other
scope hosts; the runner never adds a URL host, so list it in the scope
file first (`authorization.type: written` with the event rules as the
reference). `--target ./handouts` may be added for the statement files.

For your own challenges, pass their directory as `--target` and list any
challenge host in the scope file.

## Evidence

| Artifact | Content |
| --- | --- |
| `artifacts/challenges.txt` | Inventory: challenge, category, files or URL |
| `artifacts/<challenge>-solve.sh` or `.py` | Solve script; prints the flag, does not contain it |
| `artifacts/<challenge>-check.txt` | Masked flag and the checker's verdict |
| `artifacts/<challenge>-notes.txt` | Raw tool output behind an unsolved lead |
| `artifacts/lab-build.log`, `artifacts/lab-reset.log` | Lab start and reset, when the target is ctf-lab |

## Safety

- Only challenge files in the target and hosts in the scope are touched.
- No brute force against a remote service, no denial of service, no attack
  on CTF infrastructure, other players or the scoreboard.
- Flags are masked in the evidence and never sent anywhere but the checker.
- Binaries from a challenge are run only inside the sandbox.
- "Never read `ctf-build/.server/`" is an instruction to the agent, not a
  sandbox control: the file stays readable inside the container and only the
  prompt gates it. The eval fails a run whose artifacts or report show it
  was used.

## Variants

- Linux: `kalilinux/kali-rolling` through `kits/base-kali`, with
  `kits/lab-tools` and a small set of Kali packages.
- macOS: planned, through macsbx.

## Licences

The method is inspired by ljagiello/ctf-skills (MIT). The skills here are
original text; that project is linked as a source, not copied.

| Tool | Licence | How it is used |
| --- | --- | --- |
| ExifTool | Artistic-1.0-Perl or GPL-1.0-or-later | Kali package, run only |
| binutils, gdb | GPL-3.0 | Kali packages, run only; never vendored |
| radare2 | LGPL-3.0 | Kali package, run only; never vendored |
| binwalk | MIT | Kali package |
| pycryptodome | BSD-2-Clause | Kali package |
| xxd, file, netcat-openbsd | Vim licence, BSD-2-Clause, BSD | Kali packages |
