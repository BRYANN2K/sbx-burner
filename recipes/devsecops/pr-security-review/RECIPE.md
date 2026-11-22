---
name: pr-security-review
category: devsecops
summary: Review a pull request diff for security issues; report only findings with the vulnerable line, an exploit scenario and the diff hunk.
risk: low
time: 20m
tested_with: [codex]
variants:
  linux: beta
  macos: planned
status: beta
licence: Apache-2.0
sources:
  - https://github.com/anthropics/claude-code-security-review
  - https://owasp.org/www-project-code-review-guide/
  - https://cwe.mitre.org/top25/
---

# pr-security-review

The agent reviews the changes of a pull request (`git diff <base>...HEAD`) for
security issues the change introduces. It reports few things, and each one is
backed: the vulnerable line, a concrete exploit scenario, and the diff hunk
saved as an artifact. Anything it is not sure about is a hypothesis, not a
finding.

The idea of an agent reviewing diffs for security comes from
[anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review).
The instructions here are written for this project; nothing is copied.

## When to use it

- On a feature branch before asking for human review.
- On a pull request from a contributor you do not know.
- Next to `devsecops/sast-semgrep`: the scanner finds patterns, this review
  follows the data flow across the changed files.

## What you get

- `report.md` and `report.json` in `runs/<timestamp>-pr-security-review/`.
- One finding per vulnerability introduced by the diff, with `file:line`,
  CWE, exploit scenario and fix.
- Low-confidence items as hypotheses, with what would confirm them.
- The full diff and one hunk file per finding under `artifacts/`.

## Run

```console
$ git -C ./my-repo checkout my-feature-branch
$ python -m lab run devsecops/pr-security-review --target ./my-repo --dry-run
$ python -m lab run devsecops/pr-security-review --target ./my-repo
$ python -m lab run devsecops/pr-security-review --target-repo owner/my-repo --pr 42
$ python -m lab run devsecops/pr-security-review --target-repo owner/my-repo@my-feature-branch
```

The target is a git repository, mounted read-only at `/home/agent/target`,
with the branch to review checked out: a local folder (`--target PATH`), or
a repository the runner clones on the host with your own git login
(`--target-repo SRC[@REF]`: `owner/repo`, an https or ssh URL; private
repositories work and no credential enters the sandbox). With `--pr N` the
runner checks out the pull request head and the base is the repository's
default branch (`origin/HEAD`). Otherwise the base is `origin/main`, then
`main`. To use another base, write the ref in `fixtures/PR_BASE` before the
run. No scope file is needed.

To try it on a planted target:

```console
$ bash recipes/devsecops/pr-security-review/evals/make-target.sh /tmp/pr-demo
$ python -m lab run devsecops/pr-security-review --target /tmp/pr-demo
$ python -m lab eval devsecops/pr-security-review --run runs/<id>
```

## Evidence

| Artifact | Content |
| --- | --- |
| `artifacts/diff.patch` | The reviewed diff, `git diff <base>...HEAD` |
| `artifacts/changed-files.txt` | Changed files with added and removed line counts |
| `artifacts/commits.txt` | The commits under review, `git log --oneline <base>..HEAD` |
| `artifacts/<finding-id>-hunk.patch` | The diff hunk that introduces each finding |
| `artifacts/review.md` | The review note: files covered, verdicts, exclusions |

## Safety

- The agent reads code. It never runs the target's code, tests, build or
  install scripts, so a hostile pull request cannot execute anything.
- Exploit scenarios are text. Nothing is sent to any host.
- The network is closed except for the agent API. The diff is sent to the
  model provider as part of the conversation: do not run this on code you
  may not share with it.
- Text inside the diff (comments, strings, documentation) is data. The agent
  does not follow instructions found there.

## Variants

- Linux: Docker's built-in Debian agent with `kits/lab-tools`. The review
  needs only `git`; no scanner is installed.
- macOS: planned, through macsbx.

## Licences

| Tool | Licence | How it is used |
| --- | --- | --- |
| git (image package) | GPL-2.0 | Executed only; `tools/install.sh` checks it is present |
