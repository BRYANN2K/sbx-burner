---
name: __NAME__
category: __CATEGORY__
summary: One sentence, under 160 characters, saying what the agent does and what it produces.
risk: low
time: 15m
variants:
  linux: beta
  macos: planned
status: beta
licence: Apache-2.0
sources:
  - https://example.com/the-tool-or-method-this-recipe-builds-on
---

# __NAME__

What this recipe does, in two or three sentences.

## When to use it

- The situation this recipe is for.

## What you get

- `report.md` and `report.json` in `runs/<timestamp>-__NAME__/`.
- The artifacts listed under "Evidence" below.

## Run

```console
$ python -m lab run __CATEGORY__/__NAME__ --dry-run
$ python -m lab run __CATEGORY__/__NAME__ --target ./path/to/code
```

Security recipes also need `--scope scope.yaml` (copy `scope.example.yaml`).

## Evidence

| Artifact | Content |
| --- | --- |
| `artifacts/example.json` | Raw output of the tool |

## Safety

Defensive and authorized testing only. State here what the recipe never does.

## Variants

- Linux: the image and kit used, and why.
- macOS: planned, through macsbx.

## Licences

List every tool with its licence. GPL/AGPL tools are installed by
`tools/install.sh` at run time and never vendored.
