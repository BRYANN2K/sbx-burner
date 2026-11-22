# Contributing to sbx-burner

How to propose a change, what a pull request needs, and what we accept. Read by contributors and agents.

## What we welcome

- New recipes.
- Better rules in `AGENTS.md`, better skills, better scope examples.
- New evals.
- Bug fixes and docs fixes.

Open an issue first for a new recipe, so we avoid duplicates. Use the "New recipe" form.

## Branches and merging

- `main` is protected. Pull requests only.
- History is linear. Merge by squash or rebase.
- Work on a branch named `<type>/<topic>`, for example `feat/recipe-secrets-scan` or `docs/getting-started`.
- One recipe per pull request.

## Commits

Atomic [Conventional Commits](https://www.conventionalcommits.org/). One idea per commit. commitlint checks them in CI.

```
feat(recipe): add secrets-scan
fix(runner): stop on missing credential
docs(readme): add quick start
```

- Types: `feat`, `fix`, `docs`, `refactor`, `test`, `ci`, `chore`, `perf`.
- Scopes: `runner`, `recipe`, `skill`, `kit`, `docs`, `ci`.
- Write the subject in the imperative, lowercase, no final period.

## Sign-off (DCO)

Sign every commit:

```sh
git commit -s
```

This adds a `Signed-off-by` line and states that you have the right to submit the work under the project licence ([Developer Certificate of Origin](https://developercertificate.org/)). There is no CLA.

## Licence of contributions

Apache-2.0. What you contribute is licensed as the project is (inbound = outbound).

## Vendored material

- Vendor only MIT, Apache-2.0 or CC-BY material. Add attribution to `NOTICE`.
- CC-BY-SA, Semgrep rules and custom-licence sources: link them. Do not copy them.
- GPL and AGPL tools: install them with a script. Never vendor them.
- State the licence and source of everything you add, in the `sources` field of `RECIPE.md` and in the PR.

## New recipe checklist

- Start from `template/`.
- Follow the [recipe format](docs/recipe-format.md) and [writing a recipe](docs/writing-a-recipe.md).
- Security recipes include a `scope.example.yaml`.
- `recipe-lint` passes.
- The recipe's eval passes.
- Licence and sources are stated.
- No live malware, no secrets, no real targets.

## Tests and evidence

- Run the checks before you ask for review. Do not skip or delete a test to make it pass.
- Include a sample `report.md` from a real run in the PR, with its proof.
- A claim without a command, output or file does not count as evidence.

CI runs commitlint, lint and tests for `lab/`, shellcheck for scripts, yamllint, `recipe-lint` and the gallery index check. <!-- TODO(verify): confirm job names once the workflows land. -->

## Pull requests

- Fill in the PR template.
- Write the description yourself, in plain words.
- Keep the change inside its stated purpose. Every changed file should be explained.
- Say how you tested it.

## What we reject

- Recipes without a defensive purpose.
- Recipes that bypass scope or the network policy.
- Live malware, real credentials, real third-party targets.
- Vendored material with an incompatible licence.

See "Acceptable use" in [SECURITY.md](SECURITY.md).

## Security

Report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## Conduct

Be kind and direct. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
