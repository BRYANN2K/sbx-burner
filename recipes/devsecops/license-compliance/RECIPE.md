---
name: license-compliance
category: devsecops
summary: Build an SBOM with syft and check every component licence against an allow / review / deny policy file.
risk: low
time: 10m
tested_with: [codex]
variants:
  linux: beta
  macos: planned
status: beta
licence: Apache-2.0
sources:
  - https://github.com/anchore/syft
  - https://spdx.org/licenses/
  - https://cyclonedx.org/docs/1.6/json/
---

# license-compliance

The agent builds a software bill of materials (SBOM) for a project, then
checks the licence of every component against a policy file with three lists:
allow, review and deny. It reports denied licences in shipped dependencies,
and says where a licence is unknown instead of guessing.

## When to use it

- Before a release, to know what you ship and under which terms.
- When adding a dependency whose licence you have not read.
- As the licence step of `devsecops/gate`.

## What you get

- `report.md` and `report.json` in `runs/<timestamp>-license-compliance/`.
- One finding per shipped component with a denied licence, with the SPDX id,
  the component and what to do.
- Components with no declared licence, and components on the review list,
  as hypotheses with the next step.
- A CycloneDX SBOM you can keep.

## Run

```console
$ python -m lab run devsecops/license-compliance --target ./my-project --dry-run
$ python -m lab run devsecops/license-compliance --target ./my-project
$ python -m lab run devsecops/license-compliance --target-repo owner/repo@main
$ python -m lab run devsecops/license-compliance --target-image myorg/app:1.4
$ python -m lab run devsecops/license-compliance --target-image ./app-image.tar
```

A path or repo is mounted read-only at `/home/agent/target` (a repo is
cloned on the host with your own git login, private repos included). An
image is resolved on the host (local Docker first, then a pull with your
docker login, or a `docker save` tarball) and loaded in the sandbox; the
SBOM then covers what the image ships. Credentials never enter the
sandbox. No scope file is needed: the recipe contacts no target host.

The policy is `fixtures/license-policy.yaml`. Edit it before the run: the
shipped lists are an example, not legal advice.

To try it on a planted target:

```console
$ bash recipes/devsecops/license-compliance/evals/make-target.sh /tmp/licence-demo
$ python -m lab run devsecops/license-compliance --target /tmp/licence-demo
$ python -m lab eval devsecops/license-compliance --run runs/<id>
```

## Evidence

| Artifact | Content |
| --- | --- |
| `artifacts/sbom.cdx.json` | CycloneDX SBOM from syft |
| `artifacts/sbom.spdx.json` | The same SBOM as SPDX |
| `artifacts/licence-check.json` | One decision per component: allow, review, deny or unknown |
| `artifacts/licences.tsv` | Component, version and declared licence, one per line |

## Safety

- The agent reads manifests and lockfiles. It never installs the project's
  dependencies and never runs its build.
- Everything is offline: no component name leaves the sandbox.
- The report is an engineering check, not a legal opinion. The summary says
  so, and says what the SBOM could not see.

## Variants

- Linux: Docker's built-in Debian agent with the `kits/devsecops` toolbox.
- macOS: planned, through macsbx.

## Licences

| Tool | Licence | How it is used |
| --- | --- | --- |
| syft 1.57.2 | Apache-2.0 | Baked into `kits/devsecops`, or installed by `tools/install.sh` |
| `fixtures/license-check.py` | Apache-2.0 | Part of this recipe, standard library only |
