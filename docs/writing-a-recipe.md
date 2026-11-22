# Writing a recipe

Build a recipe from `template/`, test it, and open a pull request.

Read [Recipe format](recipe-format.md) first. Open a "new recipe" issue before you start, so nobody builds the same thing.

## 1. Pick the job

A good recipe does one job and ends with a report. State it in one sentence: "Scan a repo for secrets", "Triage a pcap". If it needs two sentences, split it.

Check the [roadmap](roadmap.md) for planned recipes and categories.

## 2. Copy the template

```sh
cp -r template recipes/<category>/<name>
```

Rename the folder. Fill in `RECIPE.md` and `recipe.yaml`.

## 3. Choose the image and tools

- Pick the smallest image that has what you need. Roadmap defaults: Kali for pentest, REMnux for malware, Ubuntu LTS for hardening, detection, IR and desktop, Debian slim for DevSecOps, dev and CI.
- Check the image meets the `sbx` kit floor: bash, a uid 1000 `agent` user, git and a CA store. If it does not, the kit must add them.
- Put install steps in `tools/`. Pin versions. Check hashes where upstream publishes them.

## 4. Write AGENTS.md

Write for an agent that will follow it literally.

- Say what to do, in order.
- Say what is out of bounds.
- Tell it to read the scope file first.
- Define the evidence format for each finding.
- Define stop conditions.

Keep it under about 150 lines. Put method in `skills/`.

## 5. Write the scope example

For security recipes, add `scope.example.yaml` with placeholder targets (`lab.internal`, `127.0.0.1`). Never put a real target in it. See [Scope and safety](scope-and-safety.md).

## 6. Write skills

One `SKILL.md` per method. Start with the trigger ("Use when..."), then steps, then what counts as proof.

## 7. Write the eval

The eval proves the recipe works. Use a target you control, such as a known-vulnerable container or a test file. Assert that:

- the report exists,
- each expected finding is present,
- each finding has proof,
- nothing outside the scope was contacted.

## 8. Check licences

For anything you copy or adapt:

- MIT, Apache-2.0, CC-BY: vendor it and add attribution to `NOTICE`.
- CC-BY-SA, Semgrep rules, custom licences: link to it. Do not copy.
- GPL, AGPL: install by script. Never vendor.

List every source with its licence in the `sources` field of `RECIPE.md`.

## 9. Test locally

```sh
python -m lab run <category>/<name> --dry-run
python -m lab run <category>/<name> --scope recipes/<category>/<name>/scope.example.yaml
```

Run recipe-lint and the eval as described in [CONTRIBUTING.md](../CONTRIBUTING.md).

## 10. Open the pull request

Use the PR template. List the licence and sources of everything vendored, and attach a sample `report.md` from a real run.

## Checklist

- [ ] One job, one sentence.
- [ ] `RECIPE.md` and `recipe.yaml` complete.
- [ ] `AGENTS.md` has role, scope rules, tools, evidence format, stop conditions.
- [ ] `scope.example.yaml` present for security recipes.
- [ ] Tools pinned.
- [ ] Eval passes.
- [ ] Licences and sources stated. `NOTICE` updated.
- [ ] No live malware, no secrets, no real targets.
