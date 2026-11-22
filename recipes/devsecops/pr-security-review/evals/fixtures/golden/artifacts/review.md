# Security review: pr-demo, `main...HEAD` (feature/report-export)

One commit, 5 files, 40 lines added. Reviewed every changed file; nothing
was executed.

## Findings

| ID | Severity | File | Issue |
| --- | --- | --- | --- |
| PR-001 | high | app/db.py:14 | SQL injection in `search_reports` (owner, q concatenated into the query) |
| PR-002 | high | app/export.py:9 | Path traversal in `read_export` (request name joined to EXPORT_DIR) |

## Hypotheses

- H-001: new routes `/reports/search` and `/exports` carry no
  authentication check. The existing `/reports` has none either, so a proxy
  may enforce it outside this repository.

## Excluded (exclusion list)

- `hashlib.md5` in `cache_key` (app/export.py:15): a cache key, not a
  security use.
- `subprocess.run(["git", ...])` in `build_revision` (app/export.py:19):
  fixed argument list, no input.

## Reviewed, no issue

- README.md: documentation only.
- tests/test_export.py: test code; the throwaway value is a test fixture.
- app/server.py: the added routes are the source side of PR-001/PR-002 and
  carry no sink of their own.

## Not part of this review

`/reports` trusts the `owner` parameter without identity: pre-existing in
unchanged code, noted in the summary.
