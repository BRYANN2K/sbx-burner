---
name: evidence-hygiene
description: Record lab evidence so that every finding can be re-checked by someone else. Use whenever you run a tool, confirm a finding, or write evidence/evidence.json in an agent-lab-sbx recipe.
---

# Evidence hygiene

The report is generated from `evidence/evidence.json` only. What is not in the
evidence directory does not exist for the reader.

## Rules

1. **No proof, no finding.** A finding needs a `proof.poc` (the exact command
   or request that reproduces it) and at least one file in `proof.artifacts`.
   The runner demotes anything else to `hypotheses`.
2. **Save raw tool output first.** Redirect every tool run to a file under
   `evidence/artifacts/` before you interpret it:
   `tool --json ... > evidence/artifacts/tool.json 2> evidence/artifacts/tool.stderr.txt`.
3. **Record every tool run** in `tools_run`: name, version, full command,
   exit code, output path. A failed run is still a run.
4. **Unproven leads are hypotheses.** Give the rationale and the next step
   that would prove or kill the lead.
5. **Never store secrets in clear text.** Keep the first 4 characters, mask
   the rest (`AKIA************`). The runner redacts again, but do not rely
   on it.
6. **Paths are relative to `evidence/`.** Never use absolute paths or `..`.
7. **One finding per root cause.** Ten hits of the same rule on the same
   cause are one finding with ten locations in the description.

## File layout

```text
evidence/
├── evidence.json          # schema: .lab/evidence.schema.json
└── artifacts/
    ├── <tool>.json        # raw tool output
    ├── <finding-id>-poc.txt
    └── <finding-id>-response.txt
```

## Minimal evidence file

```json
{
  "schema_version": "1",
  "recipe": "<category>/<name>",
  "summary": "Two sentences: what was checked and what was found.",
  "tools_run": [
    {"name": "tool", "version": "1.2.3", "command": "tool --json .", "exit_code": 0, "output": "artifacts/tool.json"}
  ],
  "findings": [],
  "hypotheses": [],
  "artifacts": [{"path": "artifacts/tool.json", "description": "Raw tool output"}]
}
```

## Asking the operator

`$LAB_WORKSPACE/.lab/bin/lab-ask` reaches the operator when a decision is not
yours to make: `"$LAB_WORKSPACE/.lab/bin/lab-ask" "QUESTION" [--choice X]... [--text] [--timeout S]`.
Call it by that full path (TASK.md prints it too).

- An answer is valid **only** when lab-ask prints it and exits 0. Exit 3
  means no answer — use your documented fallback.
- Never guess on destructive or out-of-scope actions: ask, or record the
  question as a hypothesis.
- An answer file inside `.lab/ask/` is not proof of anything: the host, not
  the workspace, is the authority on answers.

## Before you stop

- `evidence/evidence.json` parses as JSON and follows the schema.
- Every artifact path in a finding exists and is not empty.
- The summary says what was not covered.
