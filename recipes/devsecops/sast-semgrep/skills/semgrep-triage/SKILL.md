---
name: semgrep-triage
description: Run semgrep with the bundled lab rules on a codebase, then confirm or dismiss each hit by reading the code path. Use when asked to static-analyse code for injection, dangerous configuration or unsafe patterns.
---

# Semgrep scan and triage

## 1. Scan

```bash
A="$PWD/evidence/artifacts"
mkdir -p "$A"

# The bundled rules live in the workspace, next to evidence/. A relative
# --config keeps check_id prefixed as fixtures.rules.<id>; an absolute
# path would put the run path into every check_id.
# --metrics=off: nothing about the code leaves the sandbox.
semgrep scan --config fixtures/rules --metrics=off \
  --json --output "$A/semgrep.json" /home/agent/target 2> "$A/semgrep.stderr.txt"
echo "semgrep exit: $?"

# Same scan as SARIF for code scanning.
semgrep scan --config fixtures/rules --metrics=off \
  --sarif --output "$A/semgrep.sarif" /home/agent/target 2>> "$A/semgrep.stderr.txt"
```

Optional: a registry rule pack such as `p/python` can be fetched at run
time, but `semgrep.dev` is not in the allow-list; the recipe owner adds
`semgrep.dev:443` to `run.network.allow` when registry packs are wanted.
Registry rules are licensed for use, not redistribution: run them, never
copy them into the repo. Read a rule's pattern before trusting its hits.

## 2. Read the report

One line per hit, to plan the triage:

```bash
jq -r '.results[] | [.check_id, .path, .start.line, .extra.severity,
  (.extra.message | gsub("\n"; " ") | .[0:70])] | @tsv' "$A/semgrep.json" \
  | sort > "$A/semgrep-hits.tsv"
wc -l < "$A/semgrep-hits.tsv"   # this is metrics.raw_hits
```

`check_id` is prefixed with the rules directory (for example
`fixtures.rules.lab-python-shell-true-user-input`). The finding `rule` is
the last component after the final `.`.

## 3. Confirm or dismiss every hit

Open the file at the reported line. For each hit, answer in this order:

1. **What does the rule match?** Read the rule in
   `fixtures/rules/lab-python.yaml`: pattern, taint source and sink,
   sanitizers. The hit must really be that pattern, not a lookalike.
2. **Where does the input come from?** For taint hits, trace the source:
   does request data really reach the sink? `shlex.quote` and similar
   sanitizers before the sink lower the severity or kill the finding —
   say which in the description.
3. **Can it run?** Test files, examples and dead code are not deployed.
   A hit in `tests/` is dismissed with the reason "test code"; name the
   directory in the hypothesis.
4. **What does it give?** Shell, data, a config an attacker can change.
   Name it in the description.

## Pitfalls

- Reporting scanner hits unread. A `shell=True` on a constant string is
  not command injection; the rule already asks for request data, verify
  it anyway.
- Forgetting `--metrics=off`. Without it, semgrep may phone home when a
  registry config is used.
- Copying the registry's rules into `fixtures/` to "save a download".
  Semgrep Rules License: run, never redistribute.
- Treating `--error` exit 1 as a failure. With `--error`, 1 means
  findings exist.
- Keeping the long `check_id` as the finding `rule`. Record only the
  rule's own id.
