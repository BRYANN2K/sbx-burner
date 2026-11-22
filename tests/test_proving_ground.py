"""Tests for proving-ground/run.py (schema validation, kind check, scoring)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PG = REPO / "proving-ground"


def _load_run():
    spec = importlib.util.spec_from_file_location("pg_run", PG / "run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


run = _load_run()


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def _folder(tmp: Path, name: str, target: str, expected: str) -> Path:
    d = tmp / name
    _write(d / "target.yaml", target)
    _write(d / "EXPECTED.yaml", expected)
    return d


TARGET_OK = """\
recipe: devsecops/demo-sast
runs:
  - kind: path
    args: ["--target", "proving-ground/devsecops-demo-sast/project"]
cost: small
"""

EXPECTED_OK = """\
recipe: devsecops/demo-sast
must_find:
  - id_hint: sqli
    where: {cwe: "CWE-89"}
must_not_find:
  - where: {location: ".*safe\\\\.py.*"}
    reason: safe look-alike
min_findings: 1
max_findings: 5
"""


def _mkfolder(tmp: Path, target: str = TARGET_OK, expected: str = EXPECTED_OK) -> Path:
    return _folder(tmp, "devsecops-demo-sast", target, expected)


def _mkrecipe(tmp: Path, recipe: str, run_block: str) -> None:
    _write(tmp / "recipes" / recipe / "recipe.yaml", f"id: {recipe}\nrun:\n{run_block}")


# -- schema validation ------------------------------------------------------


def test_target_schema_accepts_minimal():
    errors = run._validate({"recipe": "devsecops/sca-osv", "runs": [{"kind": "path", "args": ["--target", "x"]}]}, run.SCHEMAS["target"])
    assert errors == []


def test_target_schema_rejects_bad_kind():
    data = {"recipe": "devsecops/sca-osv", "runs": [{"kind": "host", "args": []}]}
    assert run._validate(data, run.SCHEMAS["target"])


def test_target_schema_rejects_unknown_key():
    data = {"recipe": "devsecops/sca-osv", "runs": [{"kind": "path", "args": []}], "bogus": 1}
    assert run._validate(data, run.SCHEMAS["target"])


def test_expected_schema_accepts_doc(tmp_path):
    expected, err = run._load_yaml(_write(tmp_path / "e.yaml", EXPECTED_OK))
    assert err is None
    assert run._validate(expected, run.SCHEMAS["expected"]) == []


def test_expected_schema_rejects_missing_reason():
    data = {"recipe": "a/b", "must_not_find": [{"where": {"location": "x"}}]}
    assert run._validate(data, run.SCHEMAS["expected"])


# -- kind check / skip ------------------------------------------------------


def test_recipe_kinds_targets_and_legacy(tmp_path, monkeypatch):
    _mkrecipe(tmp_path, "devsecops/demo-sast", "  targets: [path, image]\n")
    _mkrecipe(tmp_path, "devsecops/legacy", "  target: required\n")
    monkeypatch.setattr(run, "ROOT", tmp_path)
    assert run._recipe_kinds("devsecops/demo-sast") == {"path", "image"}
    assert run._recipe_kinds("devsecops/legacy") == {"path"}
    assert run._recipe_kinds("devsecops/absent") is None


def test_check_folder_skips_absent_recipe(tmp_path, monkeypatch):
    folder = _mkfolder(tmp_path)
    monkeypatch.setattr(run, "ROOT", tmp_path)
    ok, note = run._check_folder(folder, run.argparse.Namespace(agent=None))
    assert ok and "SKIP" in note


def test_check_folder_rejects_undeclared_kind(tmp_path, monkeypatch):
    target = """\
recipe: devsecops/demo-sast
runs:
  - kind: url
    args: ["--target-url", "http://127.0.0.1:1"]
"""
    folder = _mkfolder(tmp_path, target=target)
    _mkrecipe(tmp_path, "devsecops/demo-sast", "  targets: [path]\n")
    monkeypatch.setattr(run, "ROOT", tmp_path)
    ok, note = run._check_folder(folder, run.argparse.Namespace(agent=None))
    assert not ok and "run.targets" in note


def test_check_folder_pending_only(tmp_path, monkeypatch):
    target = """\
recipe: devsecops/demo-sast
runs_pending:
  - kind: app
    args: ["--target-app", "npm start"]
"""
    folder = _mkfolder(tmp_path, target=target)
    _mkrecipe(tmp_path, "devsecops/demo-sast", "  targets: [path]\n")
    monkeypatch.setattr(run, "ROOT", tmp_path)
    ok, note = run._check_folder(folder, run.argparse.Namespace(agent=None))
    assert ok and note.startswith(run.PENDING)


def test_main_lists_pending_only_folder(tmp_path, monkeypatch, capsys):
    target = """\
recipe: devsecops/demo-sast
runs_pending:
  - kind: app
    args: ["--target-app", "npm start"]
"""
    folder = _mkfolder(tmp_path, target=target)
    _mkrecipe(tmp_path, "devsecops/demo-sast", "  targets: [path]\n")
    monkeypatch.setattr(run, "ROOT", tmp_path)
    monkeypatch.setattr(run, "PG", folder.parent)
    assert run.main(["--dry-run"]) == 0
    assert f"PENDING {folder.name}:" in capsys.readouterr().out


# -- scoring ----------------------------------------------------------------


FINDINGS = [
    {"id": "F-1", "rule": "lab-sqli", "location": "app.py:9", "cwe": "CWE-89", "severity": "high"},
    {"id": "F-2", "rule": "lab-xss", "location": "web.py:3", "cwe": "CWE-79", "severity": "medium"},
]


def test_score_full_recall():
    expected = {
        "must_find": [{"id_hint": "sqli", "where": {"cwe": "CWE-89", "location": "app\\.py.*"}}],
        "min_findings": 1,
        "max_findings": 3,
    }
    v = run.score(expected, FINDINGS)
    assert v["ok"] and v["recall"] == 1.0


def test_score_recall_miss_and_precision_leak():
    expected = {
        "must_find": [{"id_hint": "ssrf", "where": {"cwe": "CWE-918"}}],
        "must_not_find": [{"where": {"rule": "lab-xss"}, "reason": "decoy"}],
    }
    v = run.score(expected, FINDINGS)
    assert not v["ok"] and v["recall"] == 0.0 and len(v["precision_misses"]) == 1


def test_score_where_is_fullmatch():
    expected = {"must_find": [{"id_hint": "x", "where": {"cwe": "CWE-8"}}]}  # would match a prefix
    assert run.score(expected, FINDINGS)["recall"] == 0.0


def test_score_counts_bounds():
    expected = {"min_findings": 3, "max_findings": 10}
    v = run.score(expected, FINDINGS)
    assert not v["ok"] and not v["counts_ok"]


# -- results redaction ------------------------------------------------------


def test_results_hold_no_host_path_or_secret(tmp_path, monkeypatch):
    monkeypatch.setattr(run, "RESULTS_DIR", tmp_path / "results")
    home = str(Path.home())
    verdict = {
        "matched": [{"id_hint": f"key near {home}/docs", "where": {}}],
        "missed": [{"id_hint": "AKIAIOSFODNN7EXAMPLE in .env", "where": {}}],
        "precision_misses": [],
        "total": 2,
        "recall": 0.5,
        "counts_ok": True,
        "ok": False,
    }
    path = run._write_results("2026-11-21", "devsecops-demo", "devsecops/demo", verdict)
    text = path.read_text()
    assert home not in text
    assert "AKIAIOSFODNN7EXAMPLE" not in text
    assert "~/docs" in text


# -- hypotheses, artifacts, recipe eval -------------------------------------


def _evidence_dir(tmp: Path, files: dict[str, str]) -> Path:
    ev = tmp / "run" / "workspace" / "evidence"
    for rel, text in files.items():
        _write(ev / rel, text)
    return ev


def test_expected_schema_accepts_artifacts_and_hypotheses():
    data = {
        "recipe": "a/b",
        "must_hypothesize": [{"id_hint": "typo", "where": {"title": ".*reqeusts.*"}}],
        "artifacts": [{"path": "artifacts/*.cdx.json", "contains": "chi/v5@v5\\.1\\.0"}, {"path": "verify.txt"}],
        "recipe_eval_checks": ["metric", "artifact_contains"],
    }
    assert run._validate(data, run.SCHEMAS["expected"]) == []


def test_expected_schema_rejects_artifact_without_path():
    assert run._validate({"recipe": "a/b", "artifacts": [{"contains": "x"}]}, run.SCHEMAS["expected"])


def test_score_must_hypothesize():
    expected = {"must_hypothesize": [{"id_hint": "typo", "where": {"title": ".*reqeusts.*"}}]}
    assert not run.score(expected, FINDINGS, [])["ok"]
    v = run.score(expected, FINDINGS, [{"id": "H-1", "title": "dependency reqeusts looks typosquatted", "rationale": "r"}])
    assert v["ok"] and v["recall"] == 1.0


def test_score_hypothesis_does_not_satisfy_must_find():
    expected = {"must_find": [{"id_hint": "typo", "where": {"title": ".*reqeusts.*"}}]}
    v = run.score(expected, [], [{"id": "H-1", "title": "reqeusts", "rationale": "r"}])
    assert not v["ok"] and v["recall"] == 0.0


def test_score_artifacts(tmp_path):
    ev = _evidence_dir(
        tmp_path, {"artifacts/sbom.cdx.json": '{"purl": "pkg:golang/github.com/go-chi/chi/v5@v5.1.0"}', "verify.txt": "Verified OK\n"}
    )
    expected = {
        "artifacts": [
            {"path": "artifacts/*.cdx.json", "contains": "go-chi/chi/v5@v5\\.1\\.0"},
            {"path": "verify.txt", "contains": "Verified OK"},
        ]
    }
    v = run.score(expected, [], [], [ev])
    assert v["ok"] and v["recall"] == 1.0
    expected["artifacts"].append({"id_hint": "spdx", "path": "artifacts/*.spdx.json"})
    v = run.score(expected, [], [], [ev])
    assert not v["ok"] and [m["id_hint"] for m in v["missed"]] == ["spdx"]


def test_score_artifact_empty_file_is_a_miss(tmp_path):
    ev = _evidence_dir(tmp_path, {"verify.txt": ""})
    assert not run.score({"artifacts": [{"path": "verify.txt"}]}, [], [], [ev])["ok"]


def test_score_eval_failure_is_recall_miss():
    v = run.score({}, FINDINGS, eval_failures=["path: FAIL devsecops/demo (2/3 checks)"])
    assert not v["ok"] and v["recall"] == 0.0 and v["missed"][0]["id_hint"] == "recipe eval"


EVAL_YAML = """\
checks:
  - type: tool_ran
    name: syft
  - type: tool_ran
    name: cosign
  - type: min_findings
    count: 3
"""


def _canned_run(tmp: Path) -> Path:
    """A recipe with an eval and a run dir whose evidence passes the gate."""
    _mkrecipe(tmp, "devsecops/demo-sast", "  targets: [path]\n")
    _write(tmp / "recipes" / "devsecops" / "demo-sast" / "evals" / "eval.yaml", EVAL_YAML)
    evidence = {
        "schema_version": "1",
        "recipe": "devsecops/demo-sast",
        "summary": "canned",
        "tools_run": [{"name": "syft", "command": "syft dir:.", "exit_code": 0}],
        "findings": [],
        "hypotheses": [],
        "artifacts": [],
    }
    run_dir = tmp / "runs" / "r1"
    _write(run_dir / "workspace" / "evidence" / "evidence.json", run.json.dumps(evidence))
    return run_dir


def test_recipe_eval_scores_generic_checks_only(tmp_path, monkeypatch):
    run_dir = _canned_run(tmp_path)
    monkeypatch.setattr(run, "ROOT", tmp_path)
    scored, notes = run.recipe_eval("devsecops/demo-sast", run_dir)
    assert len(scored) == 1 and "cosign" in scored[0]
    assert len(notes) == 1 and notes[0].startswith("min_findings")
    scored, notes = run.recipe_eval("devsecops/demo-sast", run_dir, ["min_findings"])
    assert len(scored) == 2 and notes == []
    scored, notes = run.recipe_eval("devsecops/demo-sast", run_dir, ["all"])
    assert len(scored) == 2 and notes == []


def test_recipe_eval_missing_evidence_is_a_failure(tmp_path, monkeypatch):
    _canned_run(tmp_path)
    monkeypatch.setattr(run, "ROOT", tmp_path)
    scored, _ = run.recipe_eval("devsecops/demo-sast", tmp_path / "runs" / "absent")
    assert scored and "evidence" in scored[0]


def test_real_folder_scores_canned_run(tmp_path, monkeypatch):
    folder = _mkfolder(tmp_path)
    run_dir = tmp_path / "runs" / "r1"
    _write(run_dir / "report.json", run.json.dumps({"findings": FINDINGS[:1], "hypotheses": []}))
    _write(run_dir / "workspace" / "evidence" / "verify.txt", "Verified OK")
    exp = EXPECTED_OK + 'artifacts:\n  - {path: "verify.txt", contains: "Verified OK"}\n'
    _write(folder / "EXPECTED.yaml", exp)

    def fake_run(argv, cwd, env=None):
        return run.subprocess.CompletedProcess(argv, 0, run.json.dumps({"report": str(run_dir / "report.json")}) + "\n", "")

    monkeypatch.setattr(run, "_run", fake_run)
    monkeypatch.setattr(run, "recipe_eval", lambda *a: (["tool_ran name=x [tools run: []]"], ["metric name=y [z]"]))
    args = run.argparse.Namespace(agent=None, runner="lab")
    v = run._real_folder(folder, args)
    assert [m["id_hint"] for m in v["matched"]] == ["sqli", "artifact verify.txt"]
    assert [m["id_hint"] for m in v["missed"]] == ["recipe eval"]
    assert v["eval_notes"] == ["path: metric name=y [z]"]
    assert not v["ok"]


# -- dry run: skip rules, placeholders --------------------------------------


def test_check_folder_fails_when_recipe_dir_exists_without_yaml(tmp_path, monkeypatch):
    folder = _mkfolder(tmp_path)
    (tmp_path / "recipes" / "devsecops" / "demo-sast").mkdir(parents=True)
    monkeypatch.setattr(run, "ROOT", tmp_path)
    ok, note = run._check_folder(folder, run.argparse.Namespace(agent=None))
    assert not ok and "recipe.yaml" in note


def test_placeholder_args(tmp_path):
    args = ["--target-image", "proving-ground/.build/x/image.tar", "--target", "proving-ground/.build/x/repo", "--other", "keep"]
    out = run._placeholder_args(args, tmp_path)
    assert out[1] == str(tmp_path / "x" / "image.tar") and (tmp_path / "x" / "image.tar").is_file()
    assert out[3] == str(tmp_path / "x" / "repo") and (tmp_path / "x" / "repo").is_dir()
    assert out[4:] == ["--other", "keep"]


def test_check_folder_plans_docker_build_against_placeholder(tmp_path, monkeypatch):
    target = """\
recipe: devsecops/demo-sast
build: build.sh
runs:
  - kind: path
    args: ["--target", "proving-ground/devsecops-demo-sast/project"]
  - kind: image
    args: ["--target-image", "proving-ground/.build/devsecops-demo-sast/image.tar"]
needs: [docker]
"""
    folder = _mkfolder(tmp_path, target=target)
    _write(folder / "build.sh", "exit 1\n")
    _mkrecipe(tmp_path, "devsecops/demo-sast", "  targets: [path, image]\n")
    monkeypatch.setattr(run, "ROOT", tmp_path)
    planned = []

    def fake_run(argv, cwd, env=None):
        assert "build.sh" not in " ".join(argv)
        planned.append(argv)
        image = argv[argv.index("--target-image") + 1] if "--target-image" in argv else None
        assert image is None or Path(image).is_file()
        return run.subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(run, "_run", fake_run)
    ok, note = run._check_folder(folder, run.argparse.Namespace(agent=None))
    assert ok and "placeholder" in note and len(planned) == 2
    assert "proving-ground/.build" not in " ".join(planned[1])


# -- --real confirmation ----------------------------------------------------


def test_real_asks_before_running(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(run, "PG", tmp_path)
    _mkfolder(tmp_path)
    monkeypatch.setattr("builtins.input", lambda _prompt: "n")
    monkeypatch.setattr(run, "_real_folder", lambda *a: (_ for _ in ()).throw(AssertionError("ran")))
    assert run.main(["--real", "--runner", "lab"]) == 1
    out = capsys.readouterr().out
    assert "cost estimate" in out and "~50k tokens" in out


def test_answer_leaks_flags_expected_and_answer_readmes(tmp_path, monkeypatch):
    monkeypatch.setattr(run, "ROOT", tmp_path)
    app = tmp_path / "app"
    app.mkdir()
    (app / "server.js").write_text("console.log(1)\n")
    (app / "package.json").write_text("{}\n")
    assert run._answer_leaks(["--target-app", "app"]) == []
    (app / "README.md").write_text("# shop\n\n## Planted issues\n- IDOR\n")
    assert run._answer_leaks(["--target-app", "app"]) == ["app/README.md"]
    (app / "README.md").write_text("# shop\n")
    (app / "EXPECTED.yaml").write_text("recipe: x\n")
    assert run._answer_leaks(["--target", "app"]) == ["app/EXPECTED.yaml"]
    assert run._answer_leaks(["--target-image", "app"]) == [], "only path flags are checked"
    nm = app / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "README.md").write_text("must_find in a dependency readme is not ours\n")
    assert run._answer_leaks(["--target", "app"]) == ["app/EXPECTED.yaml"]


def test_no_committed_target_hands_out_answers():
    """Every run in the repo's proving-ground passes the leak guard."""
    for folder in run._folders(None):
        target, err = run._load_yaml(folder / "target.yaml")
        assert not err, err
        for entry in target.get("runs") or []:
            assert run._answer_leaks(entry["args"]) == [], (folder.name, entry)
