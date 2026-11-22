import json
import re
import shutil

import gen_index
import new_recipe
import pytest

from lab import cli, evals, lint, miniyaml, recipe


def _errors(repo):
    return {k: v for k, v in lint.lint_all(repo).items() if v}


def test_template_scaffold_lints_clean(make_recipe, repo):
    make_recipe()
    make_recipe("pentest", "web-demo", **{"recipe.yaml": ("scope: none", "scope: required")})
    assert _errors(repo) == {}


def test_real_repository_lints_clean():
    assert {k: v for k, v in lint.lint_all().items() if v} == {}


@pytest.mark.parametrize(
    "rel,old,new,needle",
    [
        ("RECIPE.md", "risk: low", "risk: extreme", "risk must be one of"),
        ("RECIPE.md", "name: demo", "name: other", "must match the directory"),
        ("RECIPE.md", "licence: Apache-2.0\n", "", "'licence' is missing"),
        ("RECIPE.md", "  macos: planned", "  macos: ready", "differs from RECIPE.md"),
        ("recipe.yaml", "    kit: kits/lab-tools", "    kit: kits/nope", "has no descriptor"),
        ("recipe.yaml", "  timeout_minutes: 15", "  timeout_minutes: 9000", "timeout_minutes"),
        ("recipe.yaml", "      - github.com:443", '      - "*"', "matches every host"),
        ("recipe.yaml", "shared_skills: [evidence-hygiene]", "shared_skills: [nope]", "shared skill 'nope'"),
        ("AGENTS.md", "## Stop conditions", "## The end", "'Stop conditions'"),
        ("sbxenv.yaml", 'schemaVersion: "1"', 'schemaVersion: "9"', "schemaVersion"),
        ("tools/install.sh", "set -euo pipefail", "set -e", "set -euo pipefail"),
        ("tools/install.sh", 'lab_log "nothing', 'curl https://x.test/i.sh | bash\nlab_log "nothing', "do not pipe"),
        ("run.py", "recipe_main(__file__)", "main()", "recipe_main"),
        ("skills/demo/SKILL.md", "name: demo", "name: wrong", "frontmatter name"),
        ("evals/eval.yaml", "name: example-tool", "name: other-tool", "golden fixture fails"),
        ("evals/eval.yaml", "type: no_demotions", "type: made_up", "unknown type"),
        ("evals/fixtures/golden/evidence.json", '"schema_version": "1"', '"schema_version": "2"', "evidence_schema"),
    ],
)
def test_contract_violations_are_reported(make_recipe, repo, rel, old, new, needle):
    make_recipe(**{rel: (old, new)})
    errors = "\n".join(_errors(repo).get("devsecops/demo", []))
    assert needle in errors, errors


def test_security_category_needs_required_scope(make_recipe, repo):
    make_recipe("pentest", "web-demo")
    assert any("scope must be 'required'" in e for e in _errors(repo)["pentest/web-demo"])


def test_missing_files_and_stub(make_recipe, repo):
    r = make_recipe()
    (r.path / "AGENTS.md").unlink()
    shutil.rmtree(r.path / "evals")
    errors = "\n".join(_errors(repo)["devsecops/demo"])
    assert "missing file: AGENTS.md" in errors and "eval.yaml is missing" in errors

    stub = repo / "recipes" / "apple" / "xcode-ci"
    stub.mkdir(parents=True)
    (stub / "RECIPE.md").write_text(
        "---\nname: xcode-ci\ncategory: apple\nsummary: Build and test an Xcode project.\nrisk: low\ntime: 20m\n"
        "variants:\n  linux: n/a\n  macos: planned\nstatus: planned\nlicence: Apache-2.0\n"
        "sources:\n  - https://github.com/BRYANN2K/macsbx\n---\n\n# xcode-ci\n",
        encoding="utf-8",
    )
    (stub / "recipe.yaml").write_text(
        'schema_version: "1"\nname: xcode-ci\ncategory: apple\nscope: none\nvariants:\n  linux:\n    status: n/a\n  macos:\n    status: planned\n',
        encoding="utf-8",
    )
    assert lint.lint_all(repo)["recipes.yaml"] == [], "recipe pull requests do not edit the index"
    report = lint.lint_all(repo, strict_index=True)
    assert report["apple/xcode-ci"] == []
    assert any("missing entry for recipes/apple/xcode-ci" in e for e in report["recipes.yaml"])


def test_index_drift_is_reported(make_recipe, repo):
    make_recipe()
    index = repo / "recipes.yaml"
    index.write_text(
        index.read_text().replace("risk: low", "risk: high") + "  - path: recipes/dev/ghost\n    name: ghost\n", encoding="utf-8"
    )
    errors = "\n".join(lint.lint_all(repo)["recipes.yaml"])
    assert "risk differs from RECIPE.md" in errors and "has no recipe directory" in errors and "missing 'summary'" in errors


def test_eval_engine_checks(make_recipe):
    r = make_recipe()
    spec = r.path / "evals" / "eval.yaml"
    spec.write_text(
        "checks:\n"
        "  - type: tool_ran\n    name: example-.*\n"
        "  - type: max_findings\n    count: 0\n"
        "  - type: min_findings\n    count: 1\n    where: {severity: high}\n"
        "  - type: artifact_contains\n    path: artifacts/*.json\n    pattern: results\n"
        "  - type: report_contains\n    text: No proven finding.\n"
        "  - type: report_excludes\n    pattern: AKIA[0-9A-Z]{16}\n"
        "  - type: summary_matches\n    pattern: Golden\n"
        "  - type: metric\n    name: coverage\n    min: 1\n",
        encoding="utf-8",
    )
    results = {res.check.split()[0]: res.passed for res in evals.run(r)}
    assert results == {
        "evidence_schema": True,
        "evidence_recipe": True,
        "tool_ran": True,
        "max_findings": True,
        "min_findings": False,
        "artifact_contains": True,
        "report_contains": True,
        "report_excludes": True,
        "summary_matches": True,
        "metric": False,
    }
    assert evals.run(r, r.path / "nope")[0].check == "evidence_present"


def test_artifact_absent_reads_raw_artifacts(make_recipe):
    r = make_recipe()
    golden = r.path / "evals" / "fixtures" / "golden"
    key_header = "-----BEGIN " + "PRIVATE KEY-----"  # assembled: no secret-shaped literal in the repo
    spec = r.path / "evals" / "eval.yaml"
    spec.write_text(
        "checks:\n"
        "  - type: artifact_absent\n    pattern: BEGIN [A-Z ]*PRIVATE KEY\n"
        "  - type: artifact_absent\n    path: artifacts/*.json\n    pattern: results\n",
        encoding="utf-8",
    )
    results = [res.passed for res in evals.run(r)][2:]
    assert results == [True, False], "clean artifacts pass; a matching JSON artifact fails"
    (golden / "artifacts" / "leak.txt").write_text(key_header + "\nMIIabc\n", encoding="utf-8")
    assert [res.passed for res in evals.run(r)][2] is False, "a key left in any artifact fails"


def test_gen_index_render_and_splice():
    entries = [
        {
            "path": "recipes/pentest/b",
            "name": "b",
            "category": "pentest",
            "summary": "B | pipe",
            "risk": "high",
            "status": "beta",
            "variants": {"linux": "beta", "macos": "planned"},
        },
        {
            "path": "recipes/pentest/a",
            "name": "a",
            "category": "pentest",
            "summary": "A",
            "risk": "low",
            "status": "ready",
            "variants": {"linux": "ready", "macos": "planned"},
        },
    ]
    table = gen_index.render(entries)
    rows = [line for line in table.splitlines() if line.startswith("| [")]
    assert rows[0].startswith("| [a](recipes/pentest/a/RECIPE.md) | pentest | A | low | ready | planned |")
    assert "B \\| pipe" in rows[1]
    readme = "# x\n\n<!-- recipes:start -->\nold\n<!-- recipes:end -->\n\ntail\n"
    out = gen_index.splice(readme, table)
    assert "old" not in out and out.endswith("<!-- recipes:end -->\n\ntail\n") and gen_index.splice(out, table) == out
    assert gen_index.splice("# no markers", table) is None


def test_gen_index_check_mode(tmp_path):
    index = tmp_path / "recipes.yaml"
    index.write_text(
        "recipes:\n  - path: recipes/dev/a\n    name: a\n    category: dev\n    summary: A\n    risk: low\n    status: beta\n"
        "    variants: {linux: beta, macos: planned}\n",
        encoding="utf-8",
    )
    readme = tmp_path / "README.md"
    readme.write_text("<!-- recipes:start -->\n<!-- recipes:end -->\n", encoding="utf-8")
    args = ["--readme", str(readme), "--index", str(index)]
    empty = tmp_path / "empty.yaml"
    empty.write_text("recipes: []\n", encoding="utf-8")
    assert gen_index.main(["--check", "--readme", str(readme), "--index", str(empty)]) == 0, "an empty index never fails the check"
    assert readme.read_text() == "<!-- recipes:start -->\n<!-- recipes:end -->\n"
    assert gen_index.main(["--check", *args]) == 1
    assert gen_index.main(args) == 0 and "[a](recipes/dev/a/RECIPE.md)" in readme.read_text()
    assert gen_index.main(["--check", *args]) == 0


def test_gen_index_sync(make_recipe, repo):
    make_recipe()
    new_recipe.scaffold("dev", "second", root=repo)
    assert any("missing entry" in e for e in lint.lint_all(repo, strict_index=True)["recipes.yaml"])
    args = ["--sync", "--index", str(repo / "recipes.yaml"), "--readme", str(repo / "README.md")]
    (repo / "README.md").write_text("no markers", encoding="utf-8")
    assert gen_index.main(["--check", *args]) == 1
    assert gen_index.main(args) == 0
    assert gen_index.main(["--check", *args]) == 0
    assert lint.lint_all(repo, strict_index=True)["recipes.yaml"] == []
    assert [e["name"] for e in recipe.load_index(repo / "recipes.yaml")] == ["demo", "second"]


def test_new_recipe_rejects_bad_input(repo):
    with pytest.raises(SystemExit):
        new_recipe.scaffold("nonsense", "x", root=repo)
    with pytest.raises(SystemExit):
        new_recipe.scaffold("dev", "Bad_Name", root=repo)


def test_cli_dry_run_and_scope(make_recipe, scope_file, capsys):
    r = make_recipe()
    assert cli.main(["run", str(r.path), "--dry-run"]) == 0
    assert "sbx create" in capsys.readouterr().out
    assert cli.recipe_main(str(r.path / "run.py"), ["--dry-run", "--agent", "codex"]) == 0
    assert "codex exec" in capsys.readouterr().out
    assert cli.main(["run", "no-such-recipe", "--dry-run"]) == 2
    assert cli.main(["lint", str(r.path)]) == 0
    assert cli.main(["lint", "no-such-recipe"]) == 2
    assert cli.main(["scope", str(scope_file), "--ignore-dates", "--host", "juice.lab.internal:3000"]) == 0
    assert cli.main(["scope", str(scope_file), "--ignore-dates", "--host", "example.com"]) == 2
    assert "OUT OF SCOPE" in capsys.readouterr().out


def test_recipe_find(make_recipe, repo):
    make_recipe()
    root = repo / "recipes"
    assert recipe.find("devsecops/demo", root).id == "devsecops/demo"
    assert recipe.find("demo", root).id == "devsecops/demo"
    with pytest.raises(recipe.RecipeError):
        recipe.find("missing", root)
    assert json.dumps(recipe.load_index(repo / "recipes.yaml"))


# --- run.targets contract -------------------------------------------------


@pytest.mark.parametrize(
    "old,new,needle",
    [
        ("  targets: [path]", "  targets: [bogus]", "must be a list drawn from"),
        ("  targets: [path]", "  targets: [port]", "'port' requires 'image'"),
        ("  targets: [path]", "  targets: [path, demo]", "'demo' is gone"),
        ("  target: optional\n  # Accepted", "  target: none\n  # Accepted", "cannot declare run.targets"),
        ("  targets: [path]", "  targets: []\n  target_health: bad", "target_health must start with"),
        ("  targets: [path]", "  targets: [path]\n  demo: fixtures/demo.sh", "run.demo is gone"),
        ("  targets: [path]", "  targets: [image]", "must mention LAB_TARGET_IMAGE"),
        ("  targets: [path]", "  targets: [url]", "must mention LAB_TARGET_URL"),
    ],
)
def test_target_contract_violations(make_recipe, repo, old, new, needle):
    make_recipe(**{"recipe.yaml": (old, new)})
    errors = "\n".join(_errors(repo).get("devsecops/demo", []))
    assert needle in errors, errors


def test_target_kinds_lint_clean_when_declared_properly(make_recipe, repo):
    recipe = make_recipe(**{"recipe.yaml": ("  targets: [path]", "  targets: [image]\n  target_health: /healthz")})
    (recipe.path / "AGENTS.md").write_text((recipe.path / "AGENTS.md").read_text() + "\nUse $LAB_TARGET_IMAGE to name the image.\n")
    import lab.recipe

    assert not lint.lint_recipe(lab.recipe.load(recipe.path), repo)


def test_ci_dry_args_picks_a_target_per_recipe(make_recipe, scope_file):
    import ci_dry_args

    def kinds(r, line):
        path = r.path / "recipe.yaml"
        path.write_text(path.read_text().replace("  targets: [path]", line).replace("  target: optional", "  target: required"))
        return r.path

    assert ci_dry_args.dry_args(make_recipe("dev", "opt").path, None) == [], "optional target: nothing to pass"
    assert ci_dry_args.dry_args(kinds(make_recipe("dev", "p"), "  targets: [path]"), None) == ["--target", "."]
    url = kinds(make_recipe("dev", "u"), "  targets: [url]")
    assert ci_dry_args.dry_args(url, scope_file) == ["--target-url", "https://juice.lab.internal:3000"]
    image = kinds(make_recipe("dev", "i"), "  targets: [image]")
    assert ci_dry_args.dry_args(image, None)[0] == "--target-image"
    with pytest.raises(SystemExit, match="no target the CI dry run can pass"):
        ci_dry_args.dry_args(url, None)


def test_gen_index_keeps_non_ascii_summaries_readable(make_recipe, repo):
    """recipes.yaml must round-trip through lab/miniyaml: no \\u escapes for non-ASCII text."""
    import gen_index

    r = make_recipe()
    md = r.path / "RECIPE.md"
    summary = "Map \u2014 then test caf\u00e9 apps"
    text = re.sub(r"(?m)^summary: .*$", f"summary: {summary}", md.read_text(encoding="utf-8"), count=1)
    md.write_text(text, encoding="utf-8")
    index = gen_index.sync_index(repo)
    assert "\\u" not in index, "summaries are written as UTF-8, not escaped"
    entry = [e for e in miniyaml.loads(index)["recipes"] if e["path"].endswith("/demo")][0]
    assert entry["summary"] == summary


def test_obsolete_agents_field_warns_and_tested_with_is_checked(make_recipe):
    from lab import lint

    recipe = make_recipe(**{"RECIPE.md": ("time: ", "agents: [claude]\ntested_with: [codex, gemini]\ntime: ")})
    errors = lint.lint_recipe(recipe, recipe.path.parents[2])
    warnings = [e for e in errors if e.startswith(lint.WARNING)]
    assert any("'agents' is obsolete" in w for w in warnings)
    assert any("tested_with: unknown agent 'gemini'" in e for e in errors if not e.startswith(lint.WARNING))


def test_agents_command_lists_the_runner_table(capsys):
    import json as _json

    from lab import cli

    assert cli.main(["agents", "--json"]) == 0
    names = [a["name"] for a in _json.loads(capsys.readouterr().out)["agents"]]
    assert names == ["claude", "codex", "cursor", "opencode", "devin"]
