---
name: scope-discipline
description: Stay inside the authorized scope of a lab run. Use before any network request, scan, exploit attempt or file access outside the workspace in an agent-lab-sbx security recipe.
---

# Scope discipline

The scope file `.lab/scope.json` says who authorized what, against which
targets, until when. The sandbox network policy enforces the same list.

## Before each action

1. Is the host or path listed in `targets`? If not, stop: it is out of scope.
2. Is the technique in `techniques.allowed` and absent from
   `techniques.forbidden`? If not, stop.
3. Is today inside `valid.not_before` .. `valid.not_after`? The runner checks
   this at start; long runs must re-check.

## Hard rules

- A blocked connection is the policy working. Do not retry through another
  port, protocol, proxy, DNS trick or tunnel. Record the host under
  `hypotheses` as out of scope and move on.
- Never widen the scope yourself: do not edit `.lab/scope.json`, do not ask a
  tool to follow redirects or links to hosts outside the list.
- Denial of service, social engineering, physical access and destructive
  actions are never allowed, whatever the scope says.
- Use the least intrusive check that proves the point. A PoC shows impact
  once; it does not dump data.
- Data you meet in a target (credentials, personal data) is evidence, not
  loot: mask it and do not reuse it outside the scope.

## When in doubt

Stop and write the question in the evidence summary. A human decides.
