---
name: triage-and-report
description: Triage candidate security findings against the evidence gate and write a clean evidence file. Use when asked to review scanner output, deduplicate findings, verify proofs, or re-triage another run's evidence in an agent-lab-sbx recipe.
---

# Triage candidates and report

The gate asks one thing: would this candidate survive as a finding when
someone re-checks it? Answer in writing, per candidate.

## 1. Load the candidates

```bash
T=/home/agent/target
mkdir -p evidence/artifacts
jq -c . "$T/candidates.jsonl"        # one object per line; fails on bad JSON
wc -l "$T/candidates.jsonl"
```

Each candidate: `id`, `title`, `tool`, `rule`, `location`, `severity`
(claimed — treat as a hint), optional `cvss` (`vector`, `score`),
`description`, `proof` (`poc`, `artifacts`: paths relative to the target),
`references`.

## 2. Answer the seven questions

Write `yes`, `no` or `n/a` for each, plus a short note. One line per
candidate in `evidence/artifacts/triage.jsonl`.

| Question | Ask yourself |
| --- | --- |
| `reproducible` | Do the stated steps alone produce the claim, starting from a defined state? |
| `in_scope` | Does the target host or path belong to this review (`.lab/scope.json` when present)? |
| `impact_shown` | Does the material show a concrete consequence, not a pattern match? |
| `root_cause` | Is it clear what in the code, config or data causes it? |
| `duplicate` | Same root cause as another candidate? Name which one. |
| `proof_present` | Does every `proof.artifacts` file exist in the target and is non-empty? |
| `precondition` | Is the attacker position it needs realistic for this system's threat model? |

Check files with `test -s "$T/<path>"` and read them. A proof file that
exists but does not show the claimed impact answers `impact_shown: no`.

## 3. Verdict

- `accepted`: `reproducible`, `impact_shown`, `root_cause`,
  `proof_present` and `precondition` are `yes`, `in_scope` is `yes` or
  `n/a`, and `duplicate` is `no`. It becomes finding `TRI-<nnn>`.
- `duplicate`: another candidate carries the same root cause. It becomes a
  hypothesis; the surviving candidate absorbs it in its description.
- `rejected`: anything else. Hypothesis: `rationale` names the failed
  answer, `next_step` the action that would prove or kill it.

Copy accepted proof into evidence, masking secrets on the way:

```bash
install -m 0644 /dev/stdin evidence/artifacts/TRI-001-response.txt <<'EOF'
...artifact text with every credential masked (first 4 chars, then *)...
EOF
```

## 4. Verify the score

For every accepted candidate that carries a CVSS vector:

```bash
python3 fixtures/cvss.py 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' \
  >> evidence/artifacts/cvss-check.txt
```

Write `cvss` = the vector with the recomputed score, and `severity` from
that score. The claimed score is a lead: if it disagrees, the vector wins.
An invalid vector is a failed `proof_present` — reject the candidate.

## 5. Report

- One finding per accepted candidate, id `TRI-<nnn>` in candidate order.
- `metrics`: `candidates`, `accepted`, `rejected` (duplicates count as
  rejected).
- The summary says how many candidates came in and why most were rejected.

## Pitfalls

- Trusting the claimed severity. Recompute or rubric; never copy it.
- Keeping a candidate because it "looks real" while its artifact is missing
  or shows nothing. That is exactly what the gate demotes.
- Two scanner names for one bug: deduplicate on root cause, not on `rule`.
- Copying a proof file that contains a credential without masking it.
- Treating "could not verify" as "false". It is a hypothesis with a next
  step — the reader decides whether to spend the effort.
