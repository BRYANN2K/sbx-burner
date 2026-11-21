# Evidence and reports

No proof, no finding. A claim without evidence goes to the hypotheses list.

## Findings

Each finding in the report has:

| Field | Content |
|---|---|
| `id` | Stable id, for example `F-001`. |
| `title` | One line. |
| `severity` | CVSS v3.1 or v4.0 vector and score, or a recipe-defined scale. State which. |
| `scope_ref` | The target from the scope file. |
| `description` | What is wrong, in plain words. |
| `proof` | What proves it. See below. |
| `impact` | What an attacker gains. |
| `fix` | A concrete remediation. |

## What counts as proof

Proof lets a reader reproduce the finding. Accepted forms:

- the exact command and its output,
- the HTTP request and response,
- a file, log excerpt or tool report with a hash,
- a failing test or a minimal reproduction.

A screenshot alone is not proof. A scanner line alone is not proof. Confirm the result by hand and record how.

## Hypotheses

Leads without proof are listed separately as `hypotheses`, with what was tried and what is missing. They never get a severity.

## Redaction

Reports are redacted before they are written:

- Secrets and tokens are masked, with the first and last characters kept so a human can match them.
- Personal data is removed or masked.
- Hosts outside the scope never appear.

## Report files

```
runs/<timestamp>-<recipe>/
├── report.md     # for people
├── report.json   # for tools
└── evidence/     # raw artifacts the report cites
```

`report.json` has these top-level keys: `recipe`, `agent`, `scope`, `started`, `finished`, `findings`, `hypotheses`, `contacts`. <!-- TODO(verify): align key names with the runner schema once lab/ lands. -->

`report.md` mirrors it: summary, scope, findings, hypotheses, contacts, appendix.

## Reports come from evidence

The reporter writes only from the evidence directory. It does not add claims the evidence does not support.

## Evals

Each recipe has evals. An eval runs the recipe against a known target and checks that:

- every expected finding appears,
- each has proof,
- no unproven item has a severity,
- no out-of-scope contact is logged.

## Retention

`runs/` is git-ignored. Do not commit run output. Clean up with `rm -r runs/<run>`.
