"""`lab scope new`: one scope per recipe, generated from the chosen target."""

from __future__ import annotations

import datetime as dt
import json
import stat

import pytest

from lab import cli, miniyaml, runner, scope_new
from lab import scope as scope_mod
from lab.recipe import discover

TODAY = dt.date(2026, 11, 22)


def _scoped_recipes():
    out = []
    for recipe in discover():
        if recipe.status == "planned" or not runner.needs_scope(recipe):
            continue
        if (recipe.path / "scope.example.yaml").is_file():
            out.append(recipe)
    return out


def _target_for(recipe):
    """The target a user would pick for this recipe."""
    kinds = set(recipe.run.get("targets") or [])
    if kinds <= {"url"} and "url" in kinds:
        return {"target_url": "https://staging.acme.dev", "reference": "contract-42"}
    if kinds & {"port", "app", "image"}:
        return {"target_port": "3000"}
    return {}


SCOPED = _scoped_recipes()


def test_every_scoped_recipe_is_covered():
    assert {r.id for r in SCOPED} >= {"pentest/api-greybox", "pentest/bug-bounty", "pentest/web-recon", "pentest/whitebox-review"}


@pytest.mark.parametrize("recipe", SCOPED, ids=lambda r: r.id)
def test_generated_scope_round_trips_through_the_loader(recipe, tmp_path):
    data, _ = scope_new.generate(recipe, owner="Test Owner", today=TODAY, **_target_for(recipe))
    path = tmp_path / "scope.yaml"
    path.write_text(scope_new.render(recipe, data), encoding="utf-8")
    assert miniyaml.loads(path.read_text(encoding="utf-8")) == data
    todo = scope_new.todos(data)
    if todo:
        with pytest.raises(scope_mod.ScopeError, match="TODO"):
            scope_mod.load(path, today=TODAY)
    else:
        scope = scope_mod.load(path, today=TODAY)
        assert scope.not_before == TODAY and scope.not_after == TODAY + dt.timedelta(days=30)
        assert scope.techniques_allowed, "the recipe's techniques were lost"
    # Techniques and network mode always come from the recipe's example.
    example = miniyaml.loads((recipe.path / "scope.example.yaml").read_text(encoding="utf-8"))
    assert data["techniques"] == scope_new._todo_replace(example["techniques"])
    assert data["network"].get("mode") == example.get("network", {}).get("mode")


def test_target_hosts():
    assert scope_new.target_hosts(target_url="https://app.acme.dev/login") == ["app.acme.dev:443"]
    assert scope_new.target_hosts(target_url="http://10.0.0.5:8080") == ["10.0.0.5:8080"]
    assert scope_new.target_hosts(target_port="8080:80") == ["localhost:8080"]
    assert scope_new.target_hosts(app_port=3000) == ["localhost:3000"]
    assert scope_new.target_hosts() == []
    with pytest.raises(scope_new.ScopeNewError):
        scope_new.target_hosts(target_url="ftp://x")


def _recipe(rid):
    return next(r for r in discover() if r.id == rid)


def test_remote_url_is_written_and_needs_a_reference(tmp_path):
    data, _ = scope_new.generate(_recipe("pentest/web-recon"), target_url="https://staging.acme.dev", owner="o", today=TODAY)
    assert data["authorization"]["type"] == "written"
    assert "TODO(burner)" in data["authorization"]["reference"]
    path = tmp_path / "s.yaml"
    path.write_text(scope_new.render(_recipe("pentest/web-recon"), data), encoding="utf-8")
    with pytest.raises(scope_mod.ScopeError, match=r"authorization.reference: still a TODO"):
        scope_mod.load(path, today=TODAY)


def test_own_lab_cannot_cover_a_remote_host():
    with pytest.raises(scope_new.ScopeNewError, match="not a lab address"):
        scope_new.generate(_recipe("pentest/web-recon"), target_url="https://staging.acme.dev", auth="own-lab", today=TODAY)


def test_bug_bounty_example_hosts_and_exclusions_are_not_kept():
    data, notes = scope_new.generate(
        _recipe("pentest/bug-bounty"), target_url="https://app.acme.dev", reference="https://acme.dev/security", owner="o", today=TODAY
    )
    hosts = [h for t in data["targets"] for h in t.get("hosts") or []]
    assert hosts == ["app.acme.dev:443"]
    assert data["network"]["deny"] == []
    assert any("network.deny" in n for n in notes)
    assert "targets[0].notes" in scope_new.todos(data)


def test_cli_writes_0600_and_never_overwrites(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("BURNER_HOME", str(tmp_path))
    args = ["scope", "new", "pentest/api-greybox", "--target-port", "3000", "--owner", "o", "--json"]
    assert cli.main(args) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["valid"] and first["written"] and first["summary"] == {"hosts": ["localhost:3000"], "auth": "own-lab", "days": 30}
    assert first["path"] == str(tmp_path / "scopes" / "api-greybox-localhost-3000.yaml")
    assert stat.S_IMODE((tmp_path / "scopes" / "api-greybox-localhost-3000.yaml").stat().st_mode) == 0o600
    assert cli.main(args) == 0
    second = json.loads(capsys.readouterr().out)
    assert second["path"].endswith("api-greybox-localhost-3000-2.yaml")


def test_cli_dry_run_writes_nothing_and_reports_todo(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("BURNER_HOME", str(tmp_path))
    code = cli.main(["scope", "new", "pentest/web-recon", "--target-url", "https://staging.acme.dev", "--dry-run", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert code == runner.EXIT_PREFLIGHT
    assert not out["written"] and not out["valid"] and out["todo"] == ["authorization.reference"]
    assert not (tmp_path / "scopes").exists()


def test_scope_check_json(tmp_path, capsys):
    data, _ = scope_new.generate(_recipe("pentest/api-greybox"), target_port="3000", owner="o")
    path = tmp_path / "s.yaml"
    path.write_text(scope_new.render(_recipe("pentest/api-greybox"), data), encoding="utf-8")
    assert cli.main(["scope", str(path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True


def test_example_lab_notes_are_dropped_for_your_target():
    data, notes = scope_new.generate(_recipe("pentest/web-recon"), target_port="8080", owner="o", today=TODAY)
    assert "notes" not in data["targets"][0]
    assert any("notes" in n for n in notes)
