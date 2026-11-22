import datetime as dt
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from lab import approve, runner, sbx

NOW = dt.datetime(2026, 11, 21, 10, 30, 0)


def _plan(recipe, repo, tmp_path, **kw):
    return runner.build_plan(recipe, runs_dir=tmp_path / "runs", now=NOW, repo_root=repo, **kw)


def _argv(plan, name):
    return next(s.argv for s in plan.all_steps() if s.name == name)


def test_plan_for_builtin_agent(make_recipe, repo, tmp_path):
    plan = _plan(make_recipe(), repo, tmp_path)
    assert plan.run_id == "20261121-103000-demo" and plan.sandbox == "lab-demo-103000"
    ws = str(tmp_path / "runs" / plan.run_id / "workspace")
    assert _argv(plan, "credentials") == ["sbx", "secret", "ls", "--service", "anthropic", "--quiet"]
    assert _argv(plan, "create") == [
        "sbx",
        "create",
        "--name",
        "lab-demo-103000",
        "--no-progress",
        "--skills",
        "off",
        "--kit",
        str(repo / "kits/lab-tools"),
        "claude",
        ws,
    ]
    assert _argv(plan, "policy-allow") == [
        "sbx",
        "policy",
        "allow",
        "network",
        "--sandbox",
        "lab-demo-103000",
        "api.anthropic.com:443",
    ]
    # The template's download hosts are install-only: open for tools, closed before the agent.
    assert _argv(plan, "policy-allow-install")[-1] == "github.com:443,release-assets.githubusercontent.com:443"
    names = [s.name for s in plan.all_steps()]
    for host in ("github.com:443", "release-assets.githubusercontent.com:443"):
        assert names.index("tools") < names.index(f"policy-close:{host}") < names.index("agent")
    assert _argv(plan, "tools") == ["sbx", "exec", "--workdir", ws, "lab-demo-103000", "--", "bash", f"{ws}/.lab/tools/install.sh"]
    agent = _argv(plan, "agent")
    assert agent[agent.index("--") + 1 : -1] == [
        "claude",
        "--dangerously-skip-permissions",
        "--output-format",
        "stream-json",
        "--verbose",
        "-p",
    ]
    assert _argv(plan, "destroy") == ["sbx", "rm", "--force", "lab-demo-103000"]
    assert not any(s.name.startswith("egress-probe") for s in plan.all_steps())
    assert not (tmp_path / "runs").exists(), "building a plan must not touch the disk"


def test_plan_for_codex_and_base_workload(make_recipe, repo, tmp_path):
    recipe = make_recipe(
        **{"recipe.yaml": ("    image: debian:stable-slim", "    image: kalilinux/kali-rolling\n    workload: kits/base-kali")}
    )
    plan = _plan(recipe, repo, tmp_path, agent_name="codex")
    create = _argv(plan, "create")
    assert create[create.index("--kit") + 1] == str(repo / "kits/agent-codex")
    assert create[-2] == str(repo / "kits/base-kali")
    assert _argv(plan, "credentials")[4] == "openai"
    assert _argv(plan, "agent")[_argv(plan, "agent").index("--") + 1 : -1] == [
        "codex",
        "exec",
        "--dangerously-bypass-approvals-and-sandbox",
        "--json",
    ]


def test_install_only_hosts_are_closed_before_the_agent(make_recipe, repo, tmp_path):
    recipe = make_recipe(
        **{
            "recipe.yaml": (
                "      - release-assets.githubusercontent.com:443\n",
                "      - release-assets.githubusercontent.com:443\n      - pypi.org:443\n",
            )
        }
    )
    plan = _plan(recipe, repo, tmp_path)
    names = [s.name for s in plan.all_steps()]
    assert _argv(plan, "policy-allow-install")[-1] == "github.com:443,release-assets.githubusercontent.com:443,pypi.org:443"
    assert _argv(plan, "policy-close:pypi.org:443") == [
        "sbx",
        "policy",
        "rm",
        "network",
        "--force",
        "--sandbox",
        "lab-demo-103000",
        "--resource",
        "pypi.org:443",
    ]
    assert names.index("policy-allow-install") < names.index("tools") < names.index("policy-close:pypi.org:443") < names.index("agent")
    assert "pypi.org:443" not in _argv(plan, "policy-allow")[-1]


def test_host_in_allow_and_install_allow_stays_open(make_recipe, repo, tmp_path):
    recipe = make_recipe(**{"recipe.yaml": ("    allow: []", "    allow:\n      - github.com:443")})
    plan = _plan(recipe, repo, tmp_path)
    names = [s.name for s in plan.all_steps()]
    assert "github.com:443" in _argv(plan, "policy-allow")[-1]
    assert _argv(plan, "policy-allow-install")[-1] == "release-assets.githubusercontent.com:443"
    assert "policy-close:github.com:443" not in names
    assert "policy-close:release-assets.githubusercontent.com:443" in names


def test_target_is_mounted_read_only(make_recipe, repo, tmp_path):
    recipe = make_recipe(**{"recipe.yaml": ("  target: optional", "  target: required")})
    with pytest.raises(runner.Refused, match="needs a target"):
        _plan(recipe, repo, tmp_path)
    code = tmp_path / "code"
    code.mkdir()
    plan = _plan(recipe, repo, tmp_path, target=str(code))
    assert _argv(plan, "create")[-1] == f"{code.resolve()}:/home/agent/target:ro"


def test_security_recipe_refuses_without_scope(make_recipe, repo, tmp_path, scope_file):
    recipe = make_recipe("pentest", "web-demo", **{"recipe.yaml": ("scope: none", "scope: required")})
    with pytest.raises(runner.Refused, match="needs a scope file"):
        _plan(recipe, repo, tmp_path)
    plan = _plan(recipe, repo, tmp_path, scope_path=str(scope_file))
    create = _argv(plan, "create")
    assert create[create.index("--deny-network") + 1] == "10.0.5.9"
    allow = _argv(plan, "policy-allow")[-1].split(",")
    assert "juice.lab.internal:3000" in allow and "10.0.5.9" not in allow
    probe = next(s for s in plan.all_steps() if s.name == "egress-probe:example.com")
    assert probe.expect_fail and probe.argv[-1] == "https://example.com"


def test_category_forces_scope_even_if_recipe_says_none(make_recipe, repo, tmp_path):
    recipe = make_recipe("malware", "triage-demo")
    assert recipe.scope_mode == "none"
    with pytest.raises(runner.Refused, match="needs a scope file"):
        _plan(recipe, repo, tmp_path)


def test_expired_scope_is_refused(make_recipe, repo, tmp_path, scope_file):
    scope_file.write_text(scope_file.read_text().replace("2026-12-31", "2026-01-02"), encoding="utf-8")
    with pytest.raises(runner.Refused, match="expired"):
        _plan(make_recipe(), repo, tmp_path, scope_path=str(scope_file))


def test_every_runner_agent_may_run_a_recipe(make_recipe, repo, tmp_path):
    recipe = make_recipe()
    assert "agents" not in recipe.meta
    for name in ("claude", "codex", "devin"):
        _plan(recipe, repo, tmp_path, agent_name=name)


def test_unknown_agent_is_refused(make_recipe, repo, tmp_path):
    recipe = make_recipe()
    with pytest.raises(runner.Refused, match="unknown agent"):
        _plan(recipe, repo, tmp_path, agent_name="gemini")


def test_render_plan_lists_commands(make_recipe, repo, tmp_path):
    text = runner.render_plan(_plan(make_recipe(), repo, tmp_path))
    assert "dry run: nothing is executed" in text
    assert "$ sbx create --name lab-demo-103000" in text
    assert ".claude/skills/demo/" in text and ".claude/skills/evidence-hygiene/" in text and "CLAUDE.md" in text


class FakeSbx:
    """Records commands; plays the agent by writing an evidence file."""

    def __init__(self, plan, fail=None, probe_open=False, write_evidence=True, secrets="anthropic\n", inspect_out="", identity_out="{}"):
        self.plan, self.calls = plan, []
        self.fail, self.probe_open, self.write_evidence, self.secrets = fail, probe_open, write_evidence, secrets
        self.inspect_out, self.identity_out = inspect_out, identity_out

    def __call__(self, argv, timeout):
        self.calls.append(argv)
        rc, out = 0, ""
        joined = " ".join(argv)
        if "sources.py" in joined and "resolve-image" in joined:
            (self.plan.run_dir / "target-identity.json").write_text(self.identity_out, encoding="utf-8")
        elif "sources.py" in joined and "repo-identity" in joined:
            Path(argv[-1]).write_text(self.identity_out, encoding="utf-8")
        elif "inspect" in joined and "docker" in joined:
            out = self.inspect_out
        elif argv[1:3] == ["secret", "ls"]:
            out = self.secrets
        elif "curl" in argv:
            rc = 0 if self.probe_open else 22
        elif "-p" in argv and self.write_evidence:
            ev = self.plan.workspace / "evidence"
            (ev / "artifacts").mkdir(parents=True, exist_ok=True)
            (ev / "artifacts" / "example.json").write_text("{}", encoding="utf-8")
            data = {
                "schema_version": "1",
                "recipe": self.plan.recipe.id,
                "summary": "Ran the tool.",
                "tools_run": [{"name": "example-tool", "command": "example-tool .", "exit_code": 0}],
                "findings": [],
                "hypotheses": [],
                "artifacts": [{"path": "artifacts/example.json", "description": "raw"}],
            }
            (ev / "evidence.json").write_text(json.dumps(data), encoding="utf-8")
        elif argv[1:3] == ["policy", "log"]:
            out = '{"allowed": [], "blocked": [{"host": "example.com"}]}'
        if self.fail and self.fail in argv:
            rc = 1
        return subprocess.CompletedProcess(argv, rc, out, "")

    def names(self):
        return [" ".join(c[1:3]) for c in self.calls]


def test_execute_happy_path(make_recipe, repo, tmp_path):
    plan = _plan(make_recipe(), repo, tmp_path)
    fake = FakeSbx(plan)
    runner.preflight(plan, execute=fake, which=lambda _: "/usr/local/bin/sbx")
    assert runner.execute_plan(plan, execute=fake, log=lambda _: None) == runner.EXIT_OK
    assert fake.names() == [
        "secret ls",
        "create --name",
        "policy allow",
        "policy allow",
        "exec --workdir",
        "policy rm",
        "policy rm",
        "exec --workdir",
        "policy log",
        "rm --force",
    ]
    ws = plan.workspace
    assert (ws / "CLAUDE.md").read_text() == "@AGENTS.md\n@TASK.md\n"
    for rel in (
        "AGENTS.md",
        "TASK.md",
        ".lab/evidence.schema.json",
        ".lab/tools/install.sh",
        ".lab/tools/lab-install.sh",
        ".claude/skills/demo/SKILL.md",
        ".claude/skills/evidence-hygiene/SKILL.md",
    ):
        assert (ws / rel).is_file(), rel
    rep = json.loads((plan.run_dir / "report.json").read_text())
    assert rep["run"]["status"] == "completed" and rep["tools_run"][0]["name"] == "example-tool"
    assert (plan.run_dir / "report.md").is_file() and (plan.run_dir / "policy-log.json").is_file()
    assert (plan.run_dir / "logs" / "agent.log").is_file()


def test_sandbox_is_destroyed_when_a_step_fails(make_recipe, repo, tmp_path):
    plan = _plan(make_recipe(), repo, tmp_path)
    fake = FakeSbx(plan, fail="bash")
    assert runner.execute_plan(plan, execute=fake, log=lambda _: None) == runner.EXIT_RUN_FAILED
    assert fake.names()[-1] == "rm --force"
    assert not any("-p" in c for c in fake.calls), "the agent must not start after a failed setup step"
    assert "failed at step tools" in (plan.run_dir / "report.md").read_text()


def test_open_egress_aborts_before_the_agent(make_recipe, repo, tmp_path, scope_file):
    recipe = make_recipe("pentest", "web-demo", **{"recipe.yaml": ("scope: none", "scope: required")})
    plan = _plan(recipe, repo, tmp_path, scope_path=str(scope_file))
    fake = FakeSbx(plan, probe_open=True)
    assert runner.execute_plan(plan, execute=fake, log=lambda _: None) == runner.EXIT_REFUSED
    assert not any("-p" in c for c in fake.calls)
    assert fake.names()[-1] == "rm --force"
    assert json.loads((plan.workspace / ".lab" / "scope.json").read_text())["id"] == "unit-lab"


def test_missing_evidence_fails_the_gate(make_recipe, repo, tmp_path):
    plan = _plan(make_recipe(), repo, tmp_path)
    assert runner.execute_plan(plan, execute=FakeSbx(plan, write_evidence=False), log=lambda _: None) == runner.EXIT_GATE_FAILED
    assert "No usable evidence file" in (plan.run_dir / "report.md").read_text()


def test_keep_skips_teardown(make_recipe, repo, tmp_path):
    plan = _plan(make_recipe(), repo, tmp_path, keep=True)
    fake = FakeSbx(plan)
    runner.execute_plan(plan, execute=fake, log=lambda _: None)
    assert "rm --force" not in fake.names()


def test_preflight_never_handles_keys(make_recipe, repo, tmp_path):
    plan = _plan(make_recipe(), repo, tmp_path)
    with pytest.raises(runner.Refused, match="sbx is not installed") as exc:
        runner.preflight(plan, execute=FakeSbx(plan), which=lambda _: None)
    assert exc.value.code == runner.EXIT_PREFLIGHT
    with pytest.raises(runner.Refused, match="sbx secret set anthropic") as exc:
        runner.preflight(plan, execute=FakeSbx(plan, secrets=""), which=lambda _: "/bin/sbx")
    assert "/login" in str(exc.value) and exc.value.code == runner.EXIT_PREFLIGHT
    assert not plan.run_dir.exists(), "preflight failure must not create anything"


def test_mixin_requires_a_credential_binding(make_recipe, repo, tmp_path, monkeypatch):
    recipe = make_recipe(
        **{"recipe.yaml": ("    image: debian:stable-slim", "    image: kalilinux/kali-rolling\n    workload: kits/base-kali")}
    )
    plan = _plan(recipe, repo, tmp_path, agent_name="codex")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    with pytest.raises(runner.Refused, match="credential binding") as exc:
        runner.preflight(plan, execute=FakeSbx(plan), which=lambda _: "/bin/sbx")
    text = str(exc.value)
    assert "chatgpt.com" in text and "run: burner approve --agent codex" in text
    assert exc.value.code == runner.EXIT_PREFLIGHT
    creds = tmp_path / "xdg" / "sbx" / "credentials.yaml"
    creds.parent.mkdir(parents=True)
    creds.write_text(
        "bindings:\n  openai:\n    oauth:\n      domains: [auth.openai.com, chatgpt.com]\n    apiKey:\n      domains: [api.openai.com]\n",
        encoding="utf-8",
    )
    runner.preflight(plan, execute=FakeSbx(plan), which=lambda _: "/bin/sbx")


def test_approve_uses_sbx_prompt_and_cleans_up(repo, tmp_path, monkeypatch, capsys):
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        if argv[1] == "create":
            # The user answering sbx's prompt records the binding.
            creds = tmp_path / "xdg" / "sbx" / "credentials.yaml"
            creds.parent.mkdir(parents=True, exist_ok=True)
            creds.write_text(
                "bindings:\n  openai:\n    oauth:\n      domains: [auth.openai.com, chatgpt.com]\n"
                "    apiKey:\n      domains: [api.openai.com]\n",
                encoding="utf-8",
            )
        return 0

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: True))
    assert approve.approve("codex", repo_root=repo, run=fake_run) == 0
    create = calls[0]
    assert create[:2] == ["sbx", "create"] and "shell" in create
    assert create[create.index("--kit") + 1].endswith("kits/agent-codex")
    assert calls[-1][:3] == ["sbx", "rm", "--force"]
    assert calls[-1][-1].startswith("burner-approve-")
    assert "approved openai" in capsys.readouterr().out


def test_approve_reports_still_missing(repo, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: True))
    assert approve.approve("codex", repo_root=repo, run=lambda argv, **kw: 0) == 3
    assert "chatgpt.com" in capsys.readouterr().out


# --- user target kinds ---------------------------------------------------

IMG_RECIPE = ("  targets: [path]", "  targets: [image, port]")


def _image_recipe(make_recipe, kinds="image, port"):
    return make_recipe(**{"recipe.yaml": ("  targets: [path]", f"  targets: [{kinds}]")})


def _retarget(recipe, new_targets):
    """Rewrite run.targets on disk and reload the recipe."""
    import lab.recipe

    path = recipe.path / "recipe.yaml"
    path.write_text(path.read_text().replace("  targets: [path]", f"  targets: [{new_targets}]"))
    return lab.recipe.load(recipe.path)


def _names(plan):
    return [s.name for s in plan.all_steps()]


def test_image_ref_resolves_on_the_host(make_recipe, repo, tmp_path):
    # Back-compat change (documented): a registry ref is now saved or pulled
    # on the HOST by target-resolve-image; the sandbox only pulls as a public
    # fallback when the host has no docker (guarded by image.json).
    recipe = _image_recipe(make_recipe)
    plan = _plan(recipe, repo, tmp_path, target_image="ghcr.io/me/app:1.2")
    names = _names(plan)
    resolve = next(s for s in plan.all_steps() if s.name == "target-resolve-image")
    assert resolve.host and "ghcr.io/me/app:1.2" in resolve.argv
    assert "image.tar" in " ".join(resolve.argv)
    allow_reg = next(s for s in plan.all_steps() if s.name == "policy-allow-registry")
    assert allow_reg.host and "ghcr.io:443" in allow_reg.argv[-1]
    pull = _argv(plan, "target-pull")
    assert pull[0] == "sbx" and "registry-sandbox" in pull[-1] and "docker pull ghcr.io/me/app:1.2" in pull[-1]
    close_reg = next(s for s in plan.all_steps() if s.name == "policy-close-registry")
    assert close_reg.host and "ghcr.io:443" in close_reg.argv[-1]
    allow = _argv(plan, "policy-allow")[-1].split(",")
    assert "ghcr.io:443" not in allow and "pkg-containers.githubusercontent.com:443" not in allow
    order = [
        "target-resolve-image",
        "create",
        "tools",
        "policy-allow-registry",
        "target-load",
        "target-pull",
        "policy-close-registry",
        "target-inspect",
        "agent",
    ]
    assert [names.index(n) for n in order] == sorted(names.index(n) for n in order)
    assert names.index("create") > names.index("target-resolve-image")
    assert plan.target_kind == "image" and plan.target_info["image"] == "ghcr.io/me/app:1.2"
    assert any(s.host for s in plan.all_steps() if s.name == "target-clean")


def test_image_ref_registry_host_derivation(make_recipe, repo, tmp_path):
    recipe = _image_recipe(make_recipe)
    hub = _plan(recipe, repo, tmp_path, target_image="nginx:1.27")
    hub_hosts = _argv(hub, "policy-allow-registry")[-1]
    assert "registry-1.docker.io:443" in hub_hosts and "auth.docker.io:443" in hub_hosts
    other = _plan(recipe, repo, tmp_path, target_image="registry.example.corp/team/app:2")
    assert "registry.example.corp:443" in _argv(other, "policy-allow-registry")[-1]
    assert any("TODO(verify): blob CDN host for registry.example.corp" in n for n in other.notes)


def test_image_tarball_is_mounted_and_loaded(make_recipe, repo, tmp_path):
    recipe = _image_recipe(make_recipe)
    tar_dir = tmp_path / "bundle"
    tar_dir.mkdir()
    tar = tar_dir / "app.tar"
    tar.write_text("fake tar")
    sibling = tar_dir / "sibling-secret.txt"
    sibling.write_text("must never reach the sandbox")
    plan = _plan(recipe, repo, tmp_path, target_image=str(tar))
    create = _argv(plan, "create")
    staged_dir = str(plan.run_dir / "target-image")
    assert f"{staged_dir}:/home/agent/target-image:ro" in create
    assert not any(str(tar_dir) in a for a in create), "the tarball's parent dir must not be mounted"
    stage = next(s for s in plan.all_steps() if s.name == "target-stage-image")
    assert stage.host and "image.tar" in stage.argv[-1]
    assert _names(plan).index("target-stage-image") < _names(plan).index("create")
    load = _argv(plan, "target-load")[-1]
    assert "docker load -q -i /home/agent/target-image/image.tar" in load and ".lab/target-image-ref" in load
    assert "target-pull" not in _names(plan)
    with pytest.raises(runner.Refused, match="tarball not found"):
        _plan(recipe, repo, tmp_path, target_image=str(tmp_path / "missing.tar"))
    with pytest.raises(runner.Refused, match="not a regular file"):
        _plan(recipe, repo, tmp_path, target_image=str(tar_dir))


def test_target_port_starts_container_and_checks_health(make_recipe, repo, tmp_path):
    recipe = _image_recipe(make_recipe)
    plan = _plan(recipe, repo, tmp_path, target_image="nginx:1.27", target_port="8080")
    joined = " ".join(_argv(plan, "target-start"))
    assert "127.0.0.1:8080:8080" in joined and "target-image-ref" in joined and "lab-target" in joined
    assert "http://localhost:8080/" in " ".join(_argv(plan, "target-health"))
    assert "localhost:8080" in _argv(plan, "policy-allow")[-1].split(",")
    assert plan.target_info["host_port"] == 8080 and plan.target_info["container_port"] == 8080
    assert any("added by the runner" in n for n in plan.notes)
    assert any("shares the sandbox egress policy" in n for n in plan.notes)


def test_target_port_host_container_form(make_recipe, repo, tmp_path):
    recipe = _image_recipe(make_recipe)
    plan = _plan(recipe, repo, tmp_path, target_image="nginx:1.27", target_port="8080:3000")
    assert "127.0.0.1:8080:3000" in " ".join(_argv(plan, "target-start"))
    assert "http://localhost:8080/" in " ".join(_argv(plan, "target-health"))
    assert "localhost:8080" in _argv(plan, "policy-allow")[-1].split(",")
    assert "localhost:3000" not in _argv(plan, "policy-allow")[-1]
    assert plan.target_info["host_port"] == 8080 and plan.target_info["container_port"] == 3000


@pytest.mark.parametrize("bad", ["0", "70000", "a:b", "8080:", ":8080", "1:2:3", "abc"])
def test_target_port_rejects_bad_input(make_recipe, repo, tmp_path, bad):
    recipe = _image_recipe(make_recipe)
    with pytest.raises(runner.Refused, match="target-port"):
        _plan(recipe, repo, tmp_path, target_image="nginx:1.27", target_port=bad)


def test_target_port_needs_an_image(make_recipe, repo, tmp_path):
    recipe = _image_recipe(make_recipe)
    with pytest.raises(runner.Refused, match="only makes sense with --target-image"):
        _plan(recipe, repo, tmp_path, target_port="8080")


def test_target_port_marks_the_in_memory_scope(make_recipe, repo, tmp_path, scope_file):
    recipe = _retarget(make_recipe("pentest", "web-demo", **{"recipe.yaml": ("scope: none", "scope: required")}), "image, port")
    plan = _plan(recipe, repo, tmp_path, scope_path=str(scope_file), target_image="nginx:1.27", target_port="8080")
    assert plan.scope.in_scope("localhost:8080")
    entry = plan.scope.raw["targets"][-1]
    assert entry["added_by_runner"] is True and entry["hosts"] == ["localhost:8080"]
    # The scope FILE itself is never rewritten.
    assert "added_by_runner" not in scope_file.read_text()
    runner.prepare_workspace(plan, repo_root=repo)
    written = json.loads((plan.workspace / ".lab" / "scope.json").read_text())
    assert written["targets"][-1]["added_by_runner"] is True


def test_target_url_requires_scope_membership(make_recipe, repo, tmp_path, scope_file):
    recipe = _retarget(make_recipe(), "url")
    with pytest.raises(runner.Refused, match="needs --scope"):
        _plan(recipe, repo, tmp_path, target_url="https://juice.lab.internal:3000")
    with pytest.raises(runner.Refused, match="not in the scope"):
        _plan(recipe, repo, tmp_path, scope_path=str(scope_file), target_url="https://app.example.com")
    with pytest.raises(runner.Refused, match="http and https"):
        _plan(recipe, repo, tmp_path, scope_path=str(scope_file), target_url="ftp://juice.lab.internal")
    plan = _plan(recipe, repo, tmp_path, scope_path=str(scope_file), target_url="https://juice.lab.internal:3000")
    assert plan.target_kind == "url" and plan.target_info["url"] == "https://juice.lab.internal:3000"
    # A URL target adds nothing to scope or policy: it was already authorized.
    assert "juice.lab.internal:3000" in _argv(plan, "policy-allow")[-1]
    assert not any(s.name.startswith("target-") for s in plan.all_steps())


def test_demo_kind_is_gone(make_recipe, repo, tmp_path):
    import lab.recipe

    assert "demo" not in lab.recipe.TARGET_KINDS
    recipe = make_recipe(**{"recipe.yaml": ("  targets: [path]", "  targets: [path, demo]\n  demo: fixtures/demo.sh")})
    with pytest.raises(runner.Refused, match="recipe is invalid"):
        _plan(recipe, repo, tmp_path, target=str(tmp_path))
    with pytest.raises(TypeError):
        _plan(make_recipe("devsecops", "plain"), repo, tmp_path, demo=True)


def test_undeclared_target_kind_is_refused(make_recipe, repo, tmp_path):
    recipe = make_recipe()  # template default: targets [path]
    with pytest.raises(runner.Refused, match="target kind 'image'"):
        _plan(recipe, repo, tmp_path, target_image="nginx:1.27")
    # A supporting path does not make an undeclared image kind acceptable.
    with pytest.raises(runner.Refused, match="target kind 'image'"):
        _plan(recipe, repo, tmp_path, target=str(tmp_path), target_image="nginx:1.27")


def test_required_target_lists_the_accepted_flags(make_recipe, repo, tmp_path):
    recipe = _retarget(make_recipe(**{"recipe.yaml": ("  target: optional", "  target: required")}), "path, image")
    with pytest.raises(runner.Refused, match="--target PATH") as exc:
        _plan(recipe, repo, tmp_path)
    assert "--target-image REF|TAR" in str(exc.value)


def test_agent_env_vars_and_task_section(make_recipe, repo, tmp_path):
    recipe = _image_recipe(make_recipe)
    plan = _plan(recipe, repo, tmp_path, target_image="nginx:1.27", target_port="8080:3000")
    agent = _argv(plan, "agent")
    env = {agent[i + 1].split("=", 1)[0]: agent[i + 1].split("=", 1)[1] for i, a in enumerate(agent) if a == "--env"}
    assert env["LAB_TARGET_KIND"] == "image"
    assert env["LAB_TARGET_IMAGE"] == "nginx:1.27"
    assert env["LAB_TARGET_URL"] == "http://localhost:8080"
    runner.prepare_workspace(plan, repo_root=repo)
    task = (plan.workspace / "TASK.md").read_text()
    assert "## Target" in task and "localhost:8080" in task and "lab-target" in task
    assert "added by the runner" in task and "shares the sandbox egress policy" in task
    assert "host port 8080 to container port 3000" in task


def test_task_md_for_url(make_recipe, repo, tmp_path, scope_file):
    recipe = _retarget(make_recipe("pentest", "web-demo", **{"recipe.yaml": ("scope: none", "scope: required")}), "url")
    plan = _plan(recipe, repo, tmp_path, scope_path=str(scope_file), target_url="https://juice.lab.internal:3000")
    runner.prepare_workspace(plan, repo_root=repo)
    task = (plan.workspace / "TASK.md").read_text()
    assert "Remote app `https://juice.lab.internal:3000` (in scope)" in task


def test_render_plan_shows_target_kind_and_value(make_recipe, repo, tmp_path):
    recipe = _image_recipe(make_recipe)
    text = runner.render_plan(_plan(recipe, repo, tmp_path, target_image="nginx:1.27", target_port="8080"))
    assert "target:    image nginx:1.27 on http://localhost:8080" in text


def test_no_credential_in_argv_or_task(make_recipe, repo, tmp_path):
    recipe = _image_recipe(make_recipe)
    plan = _plan(recipe, repo, tmp_path, target_image="ghcr.io/me/private:1")
    runner.prepare_workspace(plan, repo_root=repo)
    task = (plan.workspace / "TASK.md").read_text()
    for step in plan.all_steps():
        assert not any("TOKEN" in a.upper() or "PASSWORD" in a.upper() for a in step.argv)
    assert "sbx secret" in "\n".join(plan.notes) and "TOKEN" not in task.upper()


def test_target_inspect_records_resolved_digest(make_recipe, repo, tmp_path):
    recipe = _image_recipe(make_recipe)
    plan = _plan(recipe, repo, tmp_path, target_image="ghcr.io/me/app:1.2")
    inspect_argv = " ".join(_argv(plan, "target-inspect"))
    assert "--format" in inspect_argv and "target-image-ref" in inspect_argv
    fake = FakeSbx(
        plan,
        inspect_out="ghcr.io/me/app@sha256:abc123\n",
        identity_out='{"ref": "ghcr.io/me/app:1.2", "source": "saved", "digest": "sha256:abc123"}',
    )
    assert runner.execute_plan(plan, execute=fake, log=lambda _: None) == runner.EXIT_OK
    rep = json.loads((plan.run_dir / "report.json").read_text())
    assert rep["run"]["target"]["resolved"] == "ghcr.io/me/app@sha256:abc123"
    assert rep["run"]["target"]["source"] == "saved"
    assert "resolved: ghcr.io/me/app@sha256:abc123" in (plan.run_dir / "report.md").read_text()


def test_target_inspect_falls_back_to_image_id(make_recipe, repo, tmp_path):
    recipe = _image_recipe(make_recipe)
    tar_dir = tmp_path / "bundle"
    tar_dir.mkdir()
    (tar_dir / "app.tar").write_text("fake tar")
    plan = _plan(recipe, repo, tmp_path, target_image=str(tar_dir / "app.tar"))
    fake = FakeSbx(plan, inspect_out="sha256:deadbeef\n")
    assert runner.execute_plan(plan, execute=fake, log=lambda _: None) == runner.EXIT_OK
    rep = json.loads((plan.run_dir / "report.json").read_text())
    assert rep["run"]["target"]["resolved"] == "sha256:deadbeef"
    assert rep["run"]["target"]["kind"] == "image"


def test_recipe_without_targets_key_plans_as_before(make_recipe, repo, tmp_path):
    recipe = make_recipe(**{"recipe.yaml": ("  targets: [path]", "")})
    plan = _plan(recipe, repo, tmp_path)
    # Same step list as the pre-targets runner: nothing new appears.
    assert _names(plan) == [
        "credentials",
        "create",
        "policy-allow-install",
        "policy-allow",
        "tools",
        "policy-close:github.com:443",
        "policy-close:release-assets.githubusercontent.com:443",
        "agent",
        "policy-log",
        "destroy",
    ]


def test_sbx_builders_use_documented_flags():
    assert sbx.policy_deny("s", ["a.test", "b.test"]) == ["sbx", "policy", "deny", "network", "--sandbox", "s", "a.test,b.test"]
    assert sbx.template_save("s", "lab-x:1") == ["sbx", "template", "save", "s", "lab-x:1"]
    assert sbx.cp("s:/home/agent/x", "./x") == ["sbx", "cp", "s:/home/agent/x", "./x"]
    assert sbx.attach("s") == ["sbx", "run", "--name", "s"]
    assert sbx.policy_log("s") == ["sbx", "policy", "log", "s", "--json"]


# --- target identity (report.json run.target.identity) --------------------


def _tree(root, files):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def test_path_identity_is_a_stable_tree_digest(make_recipe, repo, tmp_path):
    recipe = make_recipe(**{"recipe.yaml": ("  target: optional", "  target: required")})
    code = _tree(tmp_path / "code", {"a.py": "print(1)\n", "pkg/b.py": "x = 2\n", ".git/HEAD": "ignored\n"})
    first = _plan(recipe, repo, tmp_path, target=str(code)).target_info["identity"]
    assert first["files"] == 2 and len(first["sha256"]) == 64, ".git/ is skipped"
    again = _plan(recipe, repo, tmp_path, target=str(code)).target_info["identity"]
    assert again["sha256"] == first["sha256"]
    (code / "pkg" / "b.py").write_text("x = 3\n")
    assert _plan(recipe, repo, tmp_path, target=str(code)).target_info["identity"]["sha256"] != first["sha256"]
    single = code / "a.py"
    import hashlib

    assert _plan(recipe, repo, tmp_path, target=str(single)).target_info["identity"] == {
        "sha256": hashlib.sha256(b"print(1)\n").hexdigest(),
        "files": 1,
    }


def test_path_identity_records_git_head_and_dirty(make_recipe, repo, tmp_path):
    recipe = make_recipe(**{"recipe.yaml": ("  target: optional", "  target: required")})
    code = _tree(tmp_path / "gitcode", {"a.py": "print(1)\n"})
    git = ["git", "-C", str(code), "-c", "user.email=t@example.test", "-c", "user.name=t"]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-qm", "init"], check=True)
    identity = _plan(recipe, repo, tmp_path, target=str(code)).target_info["identity"]
    assert len(identity["git_head"]) == 40 and identity["dirty"] is False and identity["files"] == 1
    (code / "a.py").write_text("print(2)\n")
    assert _plan(recipe, repo, tmp_path, target=str(code)).target_info["identity"]["dirty"] is True


def test_path_identity_skips_huge_trees(make_recipe, repo, tmp_path, monkeypatch):
    recipe = make_recipe(**{"recipe.yaml": ("  target: optional", "  target: required")})
    code = _tree(tmp_path / "big", {f"f{i}.txt": str(i) for i in range(3)})
    monkeypatch.setattr(runner, "PATH_DIGEST_MAX_FILES", 2)
    identity = _plan(recipe, repo, tmp_path, target=str(code)).target_info["identity"]
    assert identity == {"files": 3, "sha256": "skipped: too many files"}


def test_tarball_identity(make_recipe, repo, tmp_path):
    import hashlib

    tar = tmp_path / "bundle" / "app.tar"
    tar.parent.mkdir()
    tar.write_bytes(b"fake tar")
    plan = _plan(_image_recipe(make_recipe), repo, tmp_path, target_image=str(tar))
    assert plan.target_info["identity"]["sha256"] == hashlib.sha256(b"fake tar").hexdigest()


def test_target_url_with_credentials_is_refused(make_recipe, repo, tmp_path, scope_file):
    recipe = _retarget(make_recipe(), "url")
    for url in ("https://bob:hunter2@juice.lab.internal:3000", "https://bob@juice.lab.internal:3000"):
        with pytest.raises(runner.Refused, match="must not carry credentials"):
            _plan(recipe, repo, tmp_path, scope_path=str(scope_file), target_url=url)


def test_report_shows_the_target_identity(make_recipe, repo, tmp_path):
    recipe = make_recipe(**{"recipe.yaml": ("  target: optional", "  target: required")})
    code = _tree(tmp_path / "code", {"a.py": "print(1)\n"})
    plan = _plan(recipe, repo, tmp_path, target=str(code))
    assert runner.execute_plan(plan, execute=FakeSbx(plan), log=lambda _: None) == runner.EXIT_OK
    rep = json.loads((plan.run_dir / "report.json").read_text())
    digest = rep["run"]["target"]["identity"]["sha256"]
    assert len(digest) == 64
    assert f"sha256: {digest}" in (plan.run_dir / "report.md").read_text()


def test_supporting_path_with_an_image_or_url_target(make_recipe, repo, tmp_path, scope_file):
    recipe = _retarget(make_recipe(), "path, image, port, url")
    schema = _tree(tmp_path / "schema", {"openapi.yaml": "openapi: 3.1.0\n"})
    plan = _plan(recipe, repo, tmp_path, target=str(schema), target_image="ghcr.io/me/api:1", target_port="8080")
    assert plan.target_kind == "image"
    assert f"{schema}:/home/agent/target:ro" in _argv(plan, "create")
    assert len(plan.target_info["path_identity"]["sha256"]) == 64 and "identity" not in plan.target_info
    env = " ".join(_argv(plan, "agent"))
    assert "LAB_TARGET_PATH=/home/agent/target" in env and "LAB_TARGET_URL=http://localhost:8080" in env
    assert "Supporting files from the user" in runner.task_markdown(plan)
    plan = _plan(recipe, repo, tmp_path, scope_path=str(scope_file), target=str(schema), target_url="https://juice.lab.internal:3000")
    assert plan.target_kind == "url" and "LAB_TARGET_PATH=/home/agent/target" in " ".join(_argv(plan, "agent"))
    with pytest.raises(runner.Refused, match="exclusive"):
        _plan(recipe, repo, tmp_path, scope_path=str(scope_file), target_image="a:1", target_url="https://juice.lab.internal:3000")
    path_only = _retarget(make_recipe("devsecops", "noschema"), "image")
    with pytest.raises(runner.Refused, match="exclusive"):
        _plan(path_only, repo, tmp_path, target=str(schema), target_image="ghcr.io/me/api:1")


def test_registry_with_a_port_keeps_it(make_recipe, repo, tmp_path):
    assert runner._registry_hosts("myreg.example.com:5000/team/app:1.2")[0] == ["myreg.example.com:5000"]
    assert runner._registry_hosts("localhost:5000/app")[0] == ["localhost:5000"]
    assert runner._registry_hosts("myreg.example.com/team/app:1.2")[0] == ["myreg.example.com:443"]


def test_tarball_name_is_quoted_and_loaded_once(make_recipe, repo, tmp_path):
    recipe = _image_recipe(make_recipe)
    tar = tmp_path / "bundle" / "my app $(touch pwned).tar"
    tar.parent.mkdir()
    tar.write_bytes(b"fake tar")
    plan = _plan(recipe, repo, tmp_path, target_image=str(tar), target_port="8080:3000")
    stage = _argv(plan, "target-stage-image")[-1]
    assert "$(touch pwned).tar'" in stage, "the hostile name is single-quoted in the staging command"
    load = _argv(plan, "target-load")[-1]
    assert "docker load -q -i /home/agent/target-image/image.tar" in load
    scripts = [s.argv[-1] for s in plan.all_steps() if s.name in ("target-inspect", "target-start")]
    assert all("docker load" not in cmd and "target-image-ref" in cmd for cmd in scripts), "the tarball is loaded once"


def test_user_container_starts_after_install_hosts_close(make_recipe, repo, tmp_path):
    recipe = make_recipe(
        **{
            "recipe.yaml": (
                "  targets: [path]",
                "  targets: [image, port]",
            )
        }
    )
    plan = _plan(recipe, repo, tmp_path, target_image="ghcr.io/me/app:1.2", target_port="8080")
    names = _names(plan)
    closes = [i for i, n in enumerate(names) if n.startswith("policy-close:")]
    assert closes and names.index("target-pull") < min(closes), "the pull uses the install window"
    assert max(closes) < names.index("target-start") < names.index("target-health") < names.index("agent")
    assert "curl -s -m 5 " in _argv(plan, "target-health")[-1]


def test_agent_env_keeps_the_sandbox_path_and_points_at_lab_ask(make_recipe, repo, tmp_path):
    plan = _plan(make_recipe(), repo, tmp_path)
    agent = _argv(plan, "agent")
    assert not any(a.startswith("PATH=") for a in agent), "PATH is never overridden: tools live in several dirs"
    assert f"LAB_WORKSPACE={plan.workspace}" in agent
    assert f"{plan.workspace}/.lab/bin/lab-ask" in runner.task_markdown(plan)


# --- repo targets ---------------------------------------------------------


def test_repo_target_clones_on_host_and_mounts_ro(make_recipe, repo, tmp_path):
    recipe = _image_recipe(make_recipe, "repo")
    plan = _plan(recipe, repo, tmp_path, target_repo="owner/repo")
    names = _names(plan)
    clone = next(s for s in plan.all_steps() if s.name == "target-clone")
    assert clone.host and "clone" in clone.argv and "owner/repo" in " ".join(clone.argv)
    ident = next(s for s in plan.all_steps() if s.name == "target-identity")
    assert ident.host
    create = _argv(plan, "create")
    assert any(a.endswith(f"target-repo:{runner.TARGET_MOUNT}:ro") for a in create)
    assert names.index("target-clone") < names.index("create")
    assert plan.target_kind == "repo" and plan.target_info["repo"]
    assert "LAB_TARGET_PATH=/home/agent/target" in " ".join(_argv(plan, "agent"))
    assert any(s.name == "target-clean" and s.host for s in plan.teardown)


def test_repo_target_pr_and_submodule_flags(make_recipe, repo, tmp_path):
    recipe = _image_recipe(make_recipe, "repo")
    plan = _plan(recipe, repo, tmp_path, target_repo="https://github.com/o/r.git@v2", pr=7, with_submodules=True)
    joined = " ".join(_argv(plan, "target-clone"))
    assert "--pr" in joined and "7" in joined and "--submodules" in joined


def test_repo_target_needs_a_declared_kind(make_recipe, repo, tmp_path):
    recipe = make_recipe()
    with pytest.raises(runner.Refused):
        _plan(recipe, repo, tmp_path, target_repo="owner/repo")
    with pytest.raises(runner.Refused):
        _plan(recipe, repo, tmp_path, target_app=".")
    with pytest.raises(runner.Refused):
        _plan(_retarget(recipe, "image"), repo, tmp_path, target_repo="owner/repo")


def test_app_plus_path_supporting_files(make_recipe, repo, tmp_path):
    # A path target is supporting input only beside image/url/app primaries.
    recipe = _image_recipe(make_recipe, "app, path")
    src = tmp_path / "schema"
    src.mkdir()
    app = _app_dir(tmp_path)
    plan = _plan(recipe, repo, tmp_path, target_app=str(app), target=str(src))
    assert plan.target_kind == "app"
    create = _argv(plan, "create")
    assert any(f"{src}:{runner.TARGET_MOUNT}:ro" == a for a in create)
    import lab.recipe

    yaml_path = recipe.path / "recipe.yaml"
    yaml_path.write_text(yaml_path.read_text().replace("targets: [app, path]", "targets: [repo, path]"))
    with pytest.raises(runner.Refused):
        _plan(lab.recipe.load(recipe.path), repo, tmp_path, target_repo="owner/repo", target=str(src))


def test_repo_teardown_runs_without_sandbox(make_recipe, repo, tmp_path):
    recipe = _image_recipe(make_recipe, "repo")
    plan = _plan(recipe, repo, tmp_path, target_repo="owner/repo")
    fake = FakeSbx(plan, fail="create")
    runner.execute_plan(plan, execute=fake, log=lambda _: None)
    assert any("target-repo" in " ".join(c) for c in fake.calls if "rm" in " ".join(c) or "target-clean" == str(c))


# --- app targets ----------------------------------------------------------


def _app_dir(tmp_path, body='{"scripts": {"start": "node server.js"}}'):
    app = tmp_path / "myapp"
    app.mkdir()
    (app / "package.json").write_text(body)
    return app


def test_app_target_local_dir(make_recipe, repo, tmp_path):
    recipe = _image_recipe(make_recipe, "app")
    app = _app_dir(tmp_path)
    plan = _plan(recipe, repo, tmp_path, target_app=str(app))
    names = _names(plan)
    prep = next(s for s in plan.all_steps() if s.name == "target-app-prepare")
    assert prep.host and str(app) in prep.argv
    assert names.index("target-app-prepare") < names.index("create") < names.index("app-install")
    assert names.index("app-install") < names.index("app-start") < names.index("app-health") < names.index("agent")
    assert plan.target_kind == "app" and plan.target_info.get("port")
    assert f"http://localhost:{plan.target_info['port']}" == plan.target_info["url"]
    assert "LAB_TARGET_URL" in " ".join(_argv(plan, "agent"))


def test_app_target_repo_source(make_recipe, repo, tmp_path):
    recipe = _image_recipe(make_recipe, "app")
    plan = _plan(recipe, repo, tmp_path, target_app="owner/webapp", app_port=3000)
    names = _names(plan)
    clone = next(s for s in plan.all_steps() if s.name == "target-clone")
    assert clone.host and "app-src" in " ".join(clone.argv)
    assert names.index("target-clone") < names.index("target-app-prepare")
    assert any(s.name == "target-clean" and s.host for s in plan.teardown)
    assert plan.doctor, "a remote app source gets credential/source doctor checks"


def test_app_env_values_redacted_from_logs(make_recipe, repo, tmp_path):
    recipe = _image_recipe(make_recipe, "app")
    app = _app_dir(tmp_path)
    env_file = tmp_path / "app.env"
    env_file.write_text("DB_PASSWORD=s3cr3t-v4lue\n")
    plan = _plan(recipe, repo, tmp_path, target_app=str(app), app_env=str(env_file))
    assert "s3cr3t-v4lue" in plan.app_env_values
    assert not any("s3cr3t-v4lue" in " ".join(s.argv) for s in plan.all_steps())

    class Leaky(FakeSbx):
        def __call__(self, argv, timeout):
            proc = super().__call__(argv, timeout)
            return subprocess.CompletedProcess(argv, proc.returncode, proc.stdout + " db=s3cr3t-v4lue", proc.stderr)

    assert runner.execute_plan(plan, execute=Leaky(plan), log=lambda _: None) == runner.EXIT_OK
    for log_file in (plan.run_dir / "logs").glob("*.log"):
        assert "s3cr3t-v4lue" not in log_file.read_text()


def test_app_overrides(make_recipe, repo, tmp_path):
    recipe = _image_recipe(make_recipe, "app")
    app = _app_dir(tmp_path)
    plan = _plan(
        recipe,
        repo,
        tmp_path,
        target_app=str(app),
        app_install="npm ci",
        app_cmd="node index.js",
        app_port=9000,
        app_health="/ready",
    )
    joined = " ".join(_argv(plan, "target-app-prepare"))
    assert "npm ci" in joined and "node index.js" in joined and "9000" in joined and "/ready" in joined
    assert plan.target_info["port"] == 9000


def test_doctor_is_non_fatal(make_recipe, repo, tmp_path):
    recipe = _image_recipe(make_recipe, "repo")
    plan = _plan(recipe, repo, tmp_path, target_repo="owner/repo")
    assert plan.doctor

    class Failing(FakeSbx):
        def __call__(self, argv, timeout):
            return subprocess.CompletedProcess(argv, 1, "", "nope")

    hints = []
    runner.doctor(plan, execute=Failing(plan), log=hints.append)
    assert hints, "doctor should log a hint when a check fails"


def test_repo_clone_teardown_and_sha_in_report(make_recipe, repo, tmp_path):
    # Gate 3: the host clone is removed at teardown and the resolved commit
    # SHA lands in run.target.identity.
    recipe = _image_recipe(make_recipe, "repo")
    plan = _plan(recipe, repo, tmp_path, target_repo="owner/repo@main")
    clean = next(s for s in plan.teardown if s.name == "target-clean")
    assert clean.host and any(str(plan.run_dir / "target-repo") in a for a in clean.argv)
    sha = "3d111b33a7d9ab3cb47a4595f2b9337d2f602590"
    fake = FakeSbx(plan, identity_out=json.dumps({"repo": "https://github.com/owner/repo.git", "commit": sha, "ref": "main"}))
    assert runner.execute_plan(plan, execute=fake, log=lambda _: None) == runner.EXIT_OK
    rep = json.loads((plan.run_dir / "report.json").read_text())
    assert rep["run"]["target"]["identity"]["commit"] == sha
    assert rep["run"]["target"]["identity"]["ref"] == "main"


def test_app_install_window_and_ecosystem_hosts(make_recipe, repo, tmp_path):
    # Gate 6: app-install inside the install window; app-start/app-health
    # after the last policy-close; ecosystem hosts are install-only.
    recipe = _image_recipe(make_recipe, "app")
    app = _app_dir(tmp_path)
    plan = _plan(recipe, repo, tmp_path, target_app=str(app))
    names = _names(plan)
    closes = [i for i, n in enumerate(names) if n.startswith("policy-close:")]
    assert closes and names.index("app-install") < min(closes)
    assert max(closes) < names.index("app-start") < names.index("app-health") < names.index("agent")
    install = _argv(plan, "policy-allow-install")[-1].split(",")
    assert any("npmjs.org" in h for h in install), install
    allow = _argv(plan, "policy-allow")[-1].split(",")
    assert not any("npmjs" in h for h in allow)


def test_app_env_planted_value_absent_everywhere(make_recipe, repo, tmp_path):
    # Gate 7: --app-env values never reach argv, TASK.md, logs or reports.
    recipe = _image_recipe(make_recipe, "app")
    app = _app_dir(tmp_path)
    env_file = tmp_path / "app.env"
    env_file.write_text("DB_PASSWORD=planted-env-value\n")
    plan = _plan(recipe, repo, tmp_path, target_app=str(app), app_env=str(env_file))
    assert "planted-env-value" not in runner.task_markdown(plan)
    assert not any("planted-env-value" in " ".join(s.argv) for s in plan.all_steps())
    assert not any("planted-env-value" in str(v) for v in plan.target_info.values())

    class Leaky(FakeSbx):
        def __call__(self, argv, timeout):
            proc = super().__call__(argv, timeout)
            return subprocess.CompletedProcess(argv, proc.returncode, proc.stdout + " db=planted-env-value", proc.stderr)

    assert runner.execute_plan(plan, execute=Leaky(plan), log=lambda _: None) == runner.EXIT_OK
    for log_file in (plan.run_dir / "logs").glob("*.log"):
        assert "planted-env-value" not in log_file.read_text()
    assert "planted-env-value" not in (plan.run_dir / "report.json").read_text()
    assert "planted-env-value" not in (plan.run_dir / "report.md").read_text()


def test_doctor_reports_names_and_states_never_tokens(make_recipe, repo, tmp_path):
    # Gate 10: doctor output shows labels, states and hints only.
    token = "PLANTED_GH_TOKEN"
    recipe = _image_recipe(make_recipe, "repo")
    plan = _plan(recipe, repo, tmp_path, target_repo="owner/repo")

    class Verbose(FakeSbx):
        def __call__(self, argv, timeout):
            return subprocess.CompletedProcess(argv, 1, f"Logged in as x with {token}", "")

    lines = []
    runner.doctor(plan, execute=Verbose(plan), log=lines.append)
    assert lines, "expected doctor hints"
    assert all(token not in line for line in lines)


def test_registry_guard_reads_the_host_copy(make_recipe, repo, tmp_path):
    plan = _plan(_image_recipe(make_recipe), repo, tmp_path, target_image="ghcr.io/me/app:1.2")
    host_json = str(plan.run_dir / "target-image" / "image.json")
    for name in ("policy-allow-registry", "policy-close-registry"):
        step = next(s for s in plan.all_steps() if s.name == name)
        assert step.host and host_json in step.argv[-1] and "/home/agent/target-image" not in step.argv[-1]


def test_doctor_ls_remote_is_safe(make_recipe, repo, tmp_path):
    plan = _plan(_image_recipe(make_recipe, "path, repo"), repo, tmp_path, target_repo="https://gitlab.com/a/b.git")
    argv = next(a for name, a, _ in plan.doctor if name == "git ls-remote")
    assert "--" in argv and argv[argv.index("--") + 1] == "https://gitlab.com/a/b.git"
    assert "core.hooksPath=/dev/null" in argv and "protocol.allow=never" in argv


def test_project_env_values_are_redacted(make_recipe, repo, tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text('{"scripts": {"start": "node s.js"}}')
    (app / ".env").write_text("API_TOKEN=planted-value-123\nPORT=4000\n")
    plan = _plan(_image_recipe(make_recipe, "path, app"), repo, tmp_path, target_app=str(app))
    assert "planted-value-123" in plan.app_env_values
    assert any("own .env" in n for n in plan.notes)


@pytest.mark.parametrize("bad", ["-x", "--help", "a b", "nginx\nx", "Bad/Ref", "nginx;id"])
def test_option_like_image_refs_are_refused(make_recipe, repo, tmp_path, bad):
    with pytest.raises(runner.Refused):
        _plan(_image_recipe(make_recipe), repo, tmp_path, target_image=bad)


def test_valid_image_refs_plan(make_recipe, repo, tmp_path):
    recipe = _image_recipe(make_recipe)
    for ok in ("nginx", "ghcr.io/me/app:1.2", "localhost:5000/x/y@sha256:" + "a" * 64):
        _plan(recipe, repo, tmp_path, target_image=ok)


def test_devin_plan_uses_the_builtin_workload(make_recipe, repo, tmp_path):
    recipe = make_recipe()
    plan = _plan(recipe, repo, tmp_path, agent_name="devin")
    assert _argv(plan, "credentials") == ["sbx", "secret", "ls", "--service", "devin", "--quiet"]
    create = _argv(plan, "create")
    assert "devin" in create
    agent = _argv(plan, "agent")
    assert "--permission-mode" in agent and "dangerous" in agent and "-p" in agent


def test_app_folder_holding_the_runs_dir_is_refused(make_recipe, repo, tmp_path):
    # Bryan's run: started from the catalog folder, the app target was the
    # cwd, which holds runs/ — the copy recursed into itself.
    recipe = _image_recipe(make_recipe, "app")
    (tmp_path / "app.py").write_text("print('x')\n")
    (tmp_path / "requirements.txt").write_text("flask\n")
    with pytest.raises(runner.Refused, match="contains burner's runs folder"):
        runner.build_plan(recipe, runs_dir=tmp_path / "runs", now=NOW, repo_root=repo, target_app=str(tmp_path), app_port=8000)


def test_plan_shows_how_the_app_starts(make_recipe, repo, tmp_path):
    recipe = _image_recipe(make_recipe, "app")
    plan = _plan(recipe, repo, tmp_path, target_app=str(_app_dir(tmp_path)))
    line = next(ln for ln in runner.render_plan(plan).splitlines() if ln.startswith("  app run:"))
    assert "start: npm start" in line or "start: " in line
    assert f"port {plan.target_info['port']}" in line and "health /" in line


def _binding_plan_refuses(tmp_path, monkeypatch, text):
    from lab import sbx as sbx_mod

    cfg = tmp_path / "cfg" / "sbx"
    cfg.mkdir(parents=True)
    (cfg / "credentials.yaml").write_text(text)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    with pytest.raises(sbx_mod.BindingUnreadable):
        sbx_mod.binding_gaps({"openai": {"oauth": {"chatgpt.com"}}})


def test_binding_gaps_malformed_file_is_reported_not_crashing(tmp_path, monkeypatch):
    _binding_plan_refuses(tmp_path, monkeypatch, "bindings:\n  openai: [a,\n    b]\n")


def test_binding_gaps_wrong_shape_is_reported_not_crashing(tmp_path, monkeypatch):
    _binding_plan_refuses(tmp_path, monkeypatch, 'bindings: {openai: "str"}\n')


def test_binding_gaps_absent_file_means_all_missing(tmp_path, monkeypatch):
    from lab import sbx as sbx_mod

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "none"))
    assert sbx_mod.binding_gaps({"openai": {"oauth": {"chatgpt.com"}}}) == {"openai": {"oauth": {"chatgpt.com"}}}


def test_acknowledged_risky_techniques_are_recorded(make_recipe, repo, tmp_path):
    from tests.conftest import SCOPE_OK

    text = (
        SCOPE_OK.replace("hosts: [juice.lab.internal:3000, 10.0.5.0/24]", "hosts: [localhost:3000]")
        .replace("deny: [10.0.5.9]", "deny: []")
        .replace("allowed: [recon, scan]", "allowed: [recon, dos]\n  risky: [dos]")
    )
    path = tmp_path / "scope.yaml"
    path.write_text(text)
    recipe = make_recipe("pentest", "web-demo", **{"recipe.yaml": ("scope: none", "scope: required")})
    plan = _plan(recipe, repo, tmp_path, scope_path=str(path))
    runner.prepare_workspace(plan)
    assert "Risky techniques the operator acknowledged in the scope: dos" in (plan.workspace / "TASK.md").read_text()
    runner.execute_plan(plan, execute=FakeSbx(plan), log=lambda _: None)
    run = json.loads((plan.run_dir / "report.json").read_text())["run"]
    assert run["scope"] == {"id": "unit-lab", "risky_acknowledged": ["dos"]}
