---
name: triage-and-report
category: foundation
summary: Triage a pile of candidate findings against the evidence gate, keeping only what the supplied proof supports, and emit a clean evidence file.
risk: low
time: 15m
agents: [claude, codex]
variants:
  linux: beta
  macos: planned
status: beta
licence: Apache-2.0
sources:
  - https://www.first.org/cvss/v3.1/specification-document
  - https://github.com/elementalsouls/Claude-BugHunter
---

# triage-and-report

The agent takes a directory of candidate findings — scanner output or
another run's evidence — and applies the same bar the evidence gate applies:
no proof, no finding. Each candidate gets its triage answers in writing, a
verdict, and a clean entry in `evidence.json`. Rejected candidates become
hypotheses with the next step that would prove or kill them.

## When to use it

- After a scanner run that produced more leads than a human wants to read.
- To turn an older run's `evidence.json` plus its artifacts into a reviewed
  report.
- To learn what the gate accepts before writing a new security recipe.

## What you get

- `report.md` and `report.json` in `runs/<timestamp>-triage-and-report/`.
- `artifacts/triage.jsonl`: one line per candidate — the seven answers, the
  verdict, and the finding id it became.
- The proof artifacts that earned their finding, copied and masked.
- Metrics `candidates`, `accepted`, `rejected`.

## Run

```console
$ python -m lab run foundation/triage-and-report --target ./candidates --dry-run
$ python -m lab run foundation/triage-and-report --target ./candidates
```

The target is a directory mounted read-only at `/home/agent/target` with:

- `candidates.jsonl`: one JSON object per candidate — `id`, `title`,
  `tool`, `rule`, `location`, `severity`, `description`, optional `cvss`
  (`{vector, score}`), `proof` (`{poc, artifacts}`), `references`.
- The files `proof.artifacts` name, relative to the target directory.

A scope file is optional (`--scope scope.yaml`, copy `scope.example.yaml`).
With one, the runner also demotes findings whose target host is out of
scope — the same rule the agent applies in triage.

To try it on a planted target:

```console
$ bash recipes/foundation/triage-and-report/evals/make-target.sh /tmp/cand
$ python -m lab run foundation/triage-and-report --target /tmp/cand
$ python -m lab eval foundation/triage-and-report --run runs/<id>
```

## Evidence

| Artifact | Content |
| --- | --- |
| `artifacts/triage.jsonl` | Per candidate: the seven answers, verdict, finding id |
| `artifacts/cvss-check.txt` | The recomputed CVSS 3.1 base scores for accepted vectors |
| `artifacts/<finding-id>-*.txt` | Copied proof material, secrets masked |

## Safety

- The agent reads files and recomputes scores. It never runs the target's
  code, and never re-executes a PoC against a live service.
- Scanner severity is a lead, not the verdict: severity comes from the
  recomputed CVSS 3.1 base score, or the rubric when no vector applies.
- A credential a proof contains is evidence, not loot: it is masked in the
  copied artifact and never tested against its service.

## Variants

- Linux: Docker's built-in Debian agent with `kits/lab-tools`. `jq` and
  `python3` are installed from Debian if the image lacks them.
- macOS: planned, through macsbx.

## Licences

| Tool | Licence | How it is used |
| --- | --- | --- |
| jq | MIT | Debian package, read candidates |
| Python 3 | PSF-2.0 | Debian package; `fixtures/cvss.py` computes CVSS 3.1 base scores |

CVSS 3.1 metric names follow the FIRST specification (linked above). The
idea of a question gate before accepting findings is inspired by
elementalsouls/Claude-BugHunter (MIT / CC BY 4.0); no text is copied.
