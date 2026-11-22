# Proving ground

One small, realistic target project per recipe. Golden fixtures and evals
prove the plumbing; the proving ground proves each recipe finds real things
end to end through `burner` (or `python3 -m lab`).

## Layout

```
proving-ground/
├── run.py                     # stdlib runner; dry run is the default
├── schema/                    # target.schema.json + expected.schema.json
├── .build/                    # generated at run time (gitignored)
├── results/                   # real-run score reports (never auto-committed)
└── <category>-<name>/         # one folder per recipe
    ├── target.yaml            # recipe, runs[] (kinds + args), cost, needs
    ├── EXPECTED.yaml          # must_find / must_hypothesize / must_not_find / artifacts / min|max_findings
    ├── build.sh               # optional; builds .build/<folder>/ artifacts
    └── project/               # the target project itself
```

`runs_pending:` holds entries whose kind is not yet in the recipe's
`run.targets`; run.py skips them until the recipe update lands.

EXPECTED.yaml keys, all scored on real runs:

- `must_find`: each entry full-matches at least one finding (`where` keys are
  finding fields: rule, location, cwe, target, title, severity, tool).
- `must_hypothesize`: same shape, matched against hypotheses (id, title,
  rationale, next_step).
- `must_not_find`: decoys; a matching finding is a precision miss.
- `artifacts`: `{path, contains}` — a non-empty file under the run's
  `workspace/evidence/` matching the glob, whose text matches the regex.
- `min_findings` / `max_findings`: bounds on the finding count.

- `recipe_eval_checks`: extra recipe eval check types to score (or `all`).

Recall counts must_find, must_hypothesize, artifacts and the recipe's own
eval (the `lab eval <recipe> --run <run dir>` checks): a failed check is a
miss. Only target-agnostic check types are scored by default (evidence
schema, tool_ran, artifact_exists, artifact_absent, no_demotions): the
others are written for the recipe's own `evals/make-target.sh` target, so
their failures are listed as notes unless `recipe_eval_checks` asks for them.

Where the planted issues and decoys are, and why, lives only in EXPECTED.yaml
and this README, never in `project/` code (no comments, names or docstrings
that give the answer away).

## Folders (group A)

| folder | recipe | target | planted issues | cost |
| --- | --- | --- | --- | --- |
| devsecops-secrets-scan | devsecops/secrets-scan | git repo built into `.build/` | random AWS-shaped key in history (removed later); decoy: random generic-api-key value in `tests/test_exporter.py` | small |
| devsecops-sca-osv | devsecops/sca-osv | `project/` manifests + lockfiles | Node + Python pins with public advisories; decoy: dev-only `black==22.3.0` (GHSA-fj7x-q9j7-g6q6) | small |
| devsecops-sast-semgrep | devsecops/sast-semgrep | `project/` Express + Flask | SQLi, path traversal, SSRF; decoys: bound-parameter / allowlist versions in `files.js`, `export.py` | medium |
| pentest-whitebox-review | pentest/whitebox-review | `project/` Python service | command injection + SQLi, confirmable on localhost; decoys: unrouted `dead.py`, allowlisted `/report` | medium |
| devsecops-gate | devsecops/gate | `project/` + generated secret | secrets + vulnerable pin + SAST flaw the gate must block | medium |

## Folders (group C)

All five share `shared/vuln-node-app/` (corner-shop-api), run only in the
sandbox via `--target-image` + `--target-port`; `build.sh` also copies the
source into `.build/<folder>/app` for path mounts.

| folder | recipe | target | planted issues | cost |
| --- | --- | --- | --- | --- |
| pentest-web-recon | pentest/web-recon | shared app image (port run) | `/backup/` directory listing (finding); missing CSP in surface.json (artifact) | small |
| pentest-webapp-blackbox | pentest/webapp-blackbox | shared app image (port run) | same three, all must_find | medium |
| pentest-dast-light | pentest/dast-light | shared app image (port run) | baseline header issues the scanner provably reports | medium |
| pentest-api-greybox | pentest/api-greybox | image+port and path runs (`credentials.json` with two generated accounts) | schema-vs-live gap + basket access check | medium |
| pentest-bug-bounty | pentest/bug-bounty | **runs_pending only** | url is its only declared kind and a host URL is not sandbox-reachable | medium |

`url` runs across group C sit in `runs_pending`: a host-listening URL is not
reachable from inside the sandbox until `--target-host-port` (or an
equivalent) lands. `pentest-bug-bounty` declares only the url kind, so its
folder has no active `runs:` at all — it unblocks with the same feature.

## Run

```sh
python3 proving-ground/run.py                  # dry run: schemas, kind check, lab --dry-run plans
python3 proving-ground/run.py --only devsecops/sca-osv
python3 proving-ground/run.py --real           # real burner runs; prints cost estimate, asks to confirm
python3 proving-ground/run.py --real --yes     # same, no prompt
```

The dry run needs no network, sbx or Docker. It runs offline builds (git,
bash) and plans runs that need a Docker or network build against an empty
placeholder path. A folder is skipped only when its recipe directory is
absent from the checkout; a present recipe with an unreadable recipe.yaml
fails.

A real run needs `sbx` signed in, an agent credential, Docker or colima, and
~15 GB free disk. Every real run spends model tokens. Results land in
`proving-ground/results/<date>-<recipe>.md` with secrets redacted and host
paths rewritten (`<repo>`, `~`).

Rough cost of one real run: small ~50k, medium ~200k, large ~600k model
tokens (estimate only; it depends on the agent and the findings).

Vulnerable apps bind `127.0.0.1` only and must be run through burner / the
sandbox, never exposed on a host interface.

## Rules for builders

- Original, small, realistic code. Planted issues are fake and harmless:
  no real malware, no live secrets, no secret-shaped literal committed —
  `build.sh` generates fake values at run time.
- Git-history targets are built under `.build/`; never commit a nested `.git`.
- Images build locally at run time; no image tarballs or prebuilt binaries
  are committed. Binaries are source only, built in the sandbox.
- Known-advisory dependencies ship as manifests and lockfiles only, never
  vendored.

## Dependency alerts

`.github/dependabot.yml` has no ecosystem entry for `proving-ground/`, so no
update PRs are opened for the planted pins; `.github/codeql/codeql-config.yml`
ignores the folder.
TODO(verify): Dependabot ALERTS still come from the dependency graph and
will list the planted advisories. Bryan: add a repo-level auto-dismiss rule
for `proving-ground/**`, or turn alerts off for this repo.
