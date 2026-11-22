---
name: secrets-triage
description: Scan a git repository for leaked credentials with gitleaks and triage each hit as real or false positive. Use when asked to find secrets, API keys, tokens or passwords in code or git history.
---

# Secrets scan and triage

## 1. Scan

```bash
mkdir -p evidence/artifacts
cd /home/agent/target

# Full history. --redact keeps secrets out of the report.
gitleaks git --redact --report-format json \
  --report-path "$OLDPWD/evidence/artifacts/gitleaks.json" --exit-code 1 .
echo "gitleaks exit: $?"   # 0 = clean, 1 = leaks found, other = error

# Same scan as SARIF for code scanning.
gitleaks git --redact --report-format sarif \
  --report-path "$OLDPWD/evidence/artifacts/gitleaks.sarif" --exit-code 0 .

# Files that are not committed (ignored files, build output).
gitleaks dir --redact --report-format json \
  --report-path "$OLDPWD/evidence/artifacts/gitleaks-dir.json" --exit-code 0 .
```

If the target is not a git repository, `gitleaks git` fails: use `gitleaks dir`
only and say so in the summary.

Optional second opinion (never verifies, so nothing leaves the sandbox):

```bash
trufflehog git "file://$PWD" --no-verification --json \
  > "$OLDPWD/evidence/artifacts/trufflehog.jsonl" 2>/dev/null || true
```

## 2. Triage every hit

For each entry in `gitleaks.json` (`RuleID`, `File`, `StartLine`, `Commit`):

1. **Is it a real credential format?** Documentation samples (the AWS
   `AKIA` + 16-char example ending in `EXAMPLE`, `xxxx`, `changeme`,
   `<your-key>`) are not.
2. **Where is it?** `test/`, `fixtures/`, `examples/` lower the odds but do not
   settle it: real keys are often pasted into tests.
3. **Is it still in HEAD?** `git -C /home/agent/target grep -n "<first 4 chars>" HEAD -- <file>`.
   A secret removed from HEAD is still leaked: it lives in history.
4. **Which commit introduced it?** `git log --diff-filter=A -S"<first 8 chars>" --format='%h %ad %an' -- <file>`.
5. **What does it unlock?** Decide severity from the service, not the file.

Never test a credential against its service.

## 3. Report

- One finding per distinct credential, however many times it appears.
- Remediation is always: rotate first, then remove, then add a pre-commit
  hook (`gitleaks git --pre-commit --staged`) and, if policy requires, purge
  history.
- Dismissed hits go to `hypotheses` with the reason.

## Pitfalls

- Reporting the same key once per commit. Deduplicate on the secret.
- Treating gitleaks exit code 1 as a tool failure.
- Printing the secret while "showing" the hit. Use `--redact` and mask.
- Suggesting `git filter-repo` without rotation.
