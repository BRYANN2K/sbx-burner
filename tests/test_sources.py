"""Unit tests for lab/sources.py — host-side source handling."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from lab import sources


def test_parse_repo_shorthand_and_refs():
    url, ref = sources.parse_repo("owner/repo")
    assert url == "https://github.com/owner/repo.git" and ref is None
    url, ref = sources.parse_repo("owner/repo@v1.2")
    assert url == "https://github.com/owner/repo.git" and ref == "v1.2"
    url, ref = sources.parse_repo("https://gitlab.com/a/b.git@main")
    assert url == "https://gitlab.com/a/b.git" and ref == "main"
    url, _ = sources.parse_repo("https://example.com/x/y.git")
    assert url == "https://example.com/x/y.git"
    url, _ = sources.parse_repo("git@example.com:x/y.git")
    assert url == "git@example.com:x/y.git"


def test_parse_repo_rejects_bad_sources():
    for bad in ("", "http://insecure/x", "just-a-name", "ftp://h/r"):
        with pytest.raises(sources.SourceError):
            sources.parse_repo(bad)


def test_scrub_git_config_removes_credentials(tmp_path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text(
        '[remote "origin"]\n\turl = https://user:token@github.com/o/r.git\n[credential]\n\thelper = store\n[http]\n\textraHeader = AUTH\n'
    )
    sources.scrub_git_config(tmp_path)
    cfg = (git_dir / "config").read_text()
    assert "token" not in cfg and "helper" not in cfg and "extraHeader" not in cfg
    assert "https://github.com/o/r.git" in cfg


def test_detect_stack(tmp_path):
    assert sources.detect_stack(tmp_path) is None
    (tmp_path / "package.json").write_text('{"scripts": {"start": "node s.js"}, "dependencies": {"express": "*"}}')
    det = sources.detect_stack(tmp_path)
    assert det["ecosystem"] == "npm" and "npm" in det["install"]
    go = tmp_path / "goapp"
    go.mkdir()
    (go / "go.mod").write_text("module example.com/x\n\ngo 1.23\n")
    assert sources.detect_stack(go)["ecosystem"] == "go"


def test_ecosystem_hosts(tmp_path):
    assert any("npmjs" in h for h in sources.ecosystem_hosts("npm"))
    assert sources.ecosystem_hosts("bogus") == []


def test_parse_env_file(tmp_path):
    env = tmp_path / ".env"
    env.write_text('# comment\nKEY=value\nQUOTED="a b"\nEMPTY=\nexport X=1\n')
    parsed = sources.parse_env_file(env)
    assert parsed == {"KEY": "value", "QUOTED": "a b", "EMPTY": "", "X": "1"}


def test_copy_app_refuses_outside_symlinks(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "f.txt").write_text("x")
    (src / "escape").symlink_to("/etc/passwd")
    with pytest.raises(sources.SourceError):
        sources.copy_app(src, tmp_path / "dst")


def test_prepare_app_detects_and_writes_scripts(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "package.json").write_text('{"scripts": {"start": "node s.js"}}')
    out = sources.prepare_app(src, tmp_path / "work", install=None, cmd=None, port=None, health=None, env_file=None)
    assert out["ecosystem"] == "npm" and out["port"]
    assert (tmp_path / "work" / "app" / "package.json").is_file()


def test_resolve_image_json_layout(tmp_path):
    # argv shape is exercised in test_runner; here the file paths resolve-image
    # writes must be plain paths under the run dir.
    tar = tmp_path / "image.tar"
    ident = tmp_path / "target-identity.json"
    argv = sources.main
    assert callable(argv) and str(tar).endswith("image.tar") and str(ident).endswith("json")


# --- final-review gates ----------------------------------------------------


def test_parse_repo_refuses_forbidden_transports():
    # Gate 1b: transports and credential shapes that must never reach git.
    for bad in (
        "-malicious",
        "--upload-pack=/bin/sh",
        "ext::sh -c id",
        "fd::1",
        "file:///etc/passwd",
        "file://host/share",
        "https://user:token@github.com/o/r.git",
        "https://token@github.com/o/r.git",
        "git://h/r@",
        "owner/repo@",
    ):
        with pytest.raises(sources.SourceError):
            sources.parse_repo(bad)


def test_clone_hardening_env_and_protocol_opts(monkeypatch, tmp_path):
    # Gate 1a: every git invocation from clone_repo carries the hardened
    # argv (-c protocol.*) and env (prompt off, protocol not from user).
    calls = []
    real_run = subprocess.run

    def spy(argv, **kw):
        calls.append((argv, kw.get("env") or {}))
        if "clone" in argv:
            dest = argv[-1]
            real_run(["git", "init", "--quiet", dest], check=True)
            return subprocess.CompletedProcess(argv, 0, "", "")
        return subprocess.CompletedProcess(argv, 0, "abc123\n", "")

    monkeypatch.setattr(sources.subprocess, "run", spy)
    sources.clone_repo("owner/repo", tmp_path / "dest")
    assert calls and all(a[0][0] == "git" for a in calls)
    argv0, env0 = calls[0]
    for opt in ("protocol.allow=never", "protocol.https.allow=always", "protocol.ssh.allow=always", "protocol.git.allow=always"):
        assert opt in argv0
    assert env0["GIT_PROTOCOL_FROM_USER"] == "0" and env0["GIT_TERMINAL_PROMPT"] == "0"


def test_clone_scrubs_a_leaked_token_end_to_end(tmp_path):
    # Gate 2: a credential that sneaks into .git/config via url.insteadOf is
    # scrubbed by the real `python3 -m lab.sources clone` action.
    token = "PLANTED_TOKEN_9f3c"
    origin = tmp_path / "origin"
    work = tmp_path / "work"
    subprocess.run(["git", "init", "--bare", str(origin)], check=True, capture_output=True)
    subprocess.run(["git", "init", "--quiet", str(work)], check=True)
    (work / "f.txt").write_text("hello")
    subprocess.run(["git", "-C", str(work), "add", "."], check=True)
    subprocess.run(["git", "-C", str(work), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "--quiet", "-m", "init"], check=True)
    subprocess.run(["git", "-C", str(work), "push", "--quiet", str(origin), "HEAD:main"], check=True)
    subprocess.run(["git", "-C", str(origin), "symbolic-ref", "HEAD", "refs/heads/main"], check=True)
    port = 19418
    daemon = subprocess.Popen(
        [
            "git",
            "daemon",
            "--reuseaddr",
            "--export-all",
            "--listen=127.0.0.1",
            f"--port={port}",
            f"--base-path={tmp_path}",
            str(tmp_path),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        import time as _t

        _t.sleep(0.6)
        # A post-checkout template hook plants a tokenised remote URL and a
        # credential helper into .git/config as the clone lands — exactly what
        # the clone action's scrub must remove before the mount.
        hooks = tmp_path / "tmpl" / "hooks"
        hooks.mkdir(parents=True)
        hook = hooks / "post-checkout"
        hook.write_text(
            f'#!/bin/sh\ngit config remote.origin.url "https://user:{token}@example.com/o/r.git"\ngit config credential.helper store\n'
        )
        hook.chmod(0o755)
        env = {**os.environ, "GIT_TEMPLATE_DIR": str(tmp_path / "tmpl")}
        dest = tmp_path / "clone"
        proc = subprocess.run(
            [sys.executable, str(Path(sources.__file__).resolve()), "clone", f"git://127.0.0.1:{port}/origin", str(dest)],
            capture_output=True,
            text=True,
            env=env,
        )
        assert proc.returncode == 0, proc.stderr
        blob = "".join(p.read_text(errors="replace") for p in dest.rglob("*") if p.is_file())
        assert token not in blob, f"token leaked into the cloned tree: {proc.stdout}"
        cfg = (dest / ".git" / "config").read_text()
        assert token not in cfg and "credential.helper" not in cfg
    finally:
        daemon.terminate()


def test_path_identity_skips_outside_symlinks(tmp_path):
    # Gate 4: a symlink pointing outside the tree is never read for the digest.
    from lab import runner

    target = tmp_path / "target"
    target.mkdir()
    (target / "a.txt").write_text("inside")
    outside = tmp_path / "outside-secret"
    outside.write_text("SECRET-BLOB")
    (target / "link").symlink_to(outside)
    ident = runner._path_identity(target)
    reference = tmp_path / "ref"
    reference.mkdir()
    (reference / "a.txt").write_text("inside")
    ref_ident = runner._path_identity(reference)
    assert ident["files"] == 1 and ident["sha256"] == ref_ident["sha256"]


def test_prepare_app_never_modifies_the_user_folder(tmp_path):
    # Gate 5: copying an app source leaves the user's tree byte-identical.
    src = tmp_path / "app"
    src.mkdir()
    (src / "package.json").write_text('{"scripts": {"start": "node s.js"}}')
    (src / "s.js").write_text("// app")
    before_mtime = max(p.stat().st_mtime_ns for p in src.rglob("*"))
    before_digest = {str(p.relative_to(src)): p.read_bytes() for p in src.rglob("*") if p.is_file()}
    sources.prepare_app(src, tmp_path / "work", install=None, cmd=None, port=None, health=None, env_file=None)
    after_digest = {str(p.relative_to(src)): p.read_bytes() for p in src.rglob("*") if p.is_file()}
    assert before_digest == after_digest
    assert max(p.stat().st_mtime_ns for p in src.rglob("*")) == before_mtime


def test_detection_never_executes_project_code(tmp_path):
    # Gate 8: a hostile-looking script in package.json is data, not code.
    canary = tmp_path / "canary"
    src = tmp_path / "evil"
    src.mkdir()
    (src / "package.json").write_text('{"scripts": {"dev": "touch ' + str(canary) + '", "postinstall": "touch ' + str(canary) + '"}}')
    sources.detect_stack(src)
    sources.prepare_app(src, tmp_path / "work", install=None, cmd=None, port=None, health=None, env_file=None)
    assert not canary.exists(), "stack detection executed project code on the host"


class _FakeDocker:
    """Records host-runtime argv for resolve_image source-order tests.

    Docker answers per info_rc; Apple container is down unless container_rc=0.
    """

    def __init__(self, info_rc=0, inspect_rc=0, save_rc=0, container_rc=1):
        self.calls, self.info_rc, self.inspect_rc, self.save_rc = [], info_rc, inspect_rc, save_rc
        self.container_rc = container_rc

    def run(self, argv, **kw):
        self.calls.append(argv)
        if argv[:2] == ["docker", "info"]:
            return subprocess.CompletedProcess(argv, self.info_rc, "", "")
        if argv[:2] == ["docker", "image"]:
            return subprocess.CompletedProcess(argv, self.inspect_rc, "img@sha256:deadbeef\n" if self.inspect_rc == 0 else "", "")
        if argv[:3] == ["container", "system", "status"]:
            return subprocess.CompletedProcess(argv, self.container_rc, "", "")
        if argv[:3] == ["container", "image", "inspect"]:
            body = json.dumps([{"configuration": {"name": "ghcr.io/me/app:1", "descriptor": {"digest": "sha256:c0ffee"}}}])
            return subprocess.CompletedProcess(argv, self.inspect_rc, body if self.inspect_rc == 0 else "", "")
        if argv[:3] == ["container", "registry", "list"]:
            return subprocess.CompletedProcess(argv, 0, "HOSTNAME USERNAME\n", "")
        return subprocess.CompletedProcess(argv, self.save_rc, "", "")


@pytest.fixture(autouse=True)
def _runtimes_on_path(monkeypatch):
    # Both CLIs "exist"; availability is decided by the fake's return codes.
    monkeypatch.delenv("LAB_HOST_RUNTIME", raising=False)
    monkeypatch.setattr(sources.shutil, "which", lambda name: f"/usr/bin/{name}")


def test_image_source_order_local_first(monkeypatch, tmp_path):
    # Gate 9: local daemon -> save only, never pull.
    fake = _FakeDocker(info_rc=0, inspect_rc=0)
    monkeypatch.setattr(sources.subprocess, "run", fake.run)
    out = sources.resolve_image("ghcr.io/me/app:1", tmp_path / "t" / "image.tar")
    assert out["source"] == "local" and out["digest"] == "img@sha256:deadbeef"
    assert not any("pull" in c for c in fake.calls)
    assert ["docker", "save", "-o", str(tmp_path / "t" / "image.tar"), "--", "ghcr.io/me/app:1"] in fake.calls


def test_image_source_order_host_pull_when_missing(monkeypatch, tmp_path):
    # Gate 9: absent locally -> host pull (user's login) then save.
    fake = _FakeDocker(info_rc=0, inspect_rc=1)
    monkeypatch.setattr(sources.subprocess, "run", fake.run)
    out = sources.resolve_image("ghcr.io/me/app:1", tmp_path / "t" / "image.tar")
    assert out["source"] == "registry"
    assert ["docker", "pull", "--", "ghcr.io/me/app:1"] in fake.calls
    assert any(c[:2] == ["docker", "save"] for c in fake.calls)


def test_image_source_order_sandbox_fallback_for_public(monkeypatch, tmp_path):
    # Gate 9: no host daemon + public ref -> sandbox pull marker, no host pull.
    fake = _FakeDocker(info_rc=1)
    monkeypatch.setattr(sources.subprocess, "run", fake.run)
    out = sources.resolve_image("ghcr.io/me/app:1", tmp_path / "t" / "image.tar")
    assert out["source"] == "registry-sandbox"
    assert not any(c[:2] == ["docker", "pull"] for c in fake.calls)
    assert not (tmp_path / "t" / "image.tar").exists()


def test_image_source_order_refuses_private_without_daemon(monkeypatch, tmp_path):
    # Gate 9: no host daemon + private-looking ref -> refused, nothing pulled.
    fake = _FakeDocker(info_rc=1)
    monkeypatch.setattr(sources.subprocess, "run", fake.run)
    with pytest.raises(sources.SourceError):
        sources.resolve_image("corp.internal.example/team/app:2", tmp_path / "t" / "image.tar")
    assert not any(c[:2] == ["docker", "pull"] for c in fake.calls)


def test_docker_auth_names_only_never_tokens(monkeypatch, tmp_path):
    # Gates 9/10: registry names come out of the docker config; the planted
    # auth value never appears in argv, exceptions or output.
    token = "PLANTED_DOCKER_AUTH"
    docker_dir = tmp_path / ".docker"
    docker_dir.mkdir()
    (docker_dir / "config.json").write_text(json.dumps({"auths": {"ghcr.io": {"auth": token}}}))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    fake = _FakeDocker(info_rc=1)
    monkeypatch.setattr(sources.subprocess, "run", fake.run)
    assert "ghcr.io" in sources._docker_config_auths() and token not in str(sources._docker_config_auths())
    with pytest.raises(sources.SourceError) as exc:
        sources.resolve_image("ghcr.io/me/app:1", tmp_path / "t" / "image.tar")
    assert token not in str(exc.value)
    assert all(token not in " ".join(map(str, c)) for c in fake.calls)


def test_apple_container_used_when_docker_is_down(monkeypatch, tmp_path):
    fake = _FakeDocker(info_rc=1, inspect_rc=0, container_rc=0)
    monkeypatch.setattr(sources.subprocess, "run", fake.run)
    out = sources.resolve_image("ghcr.io/me/app:1", tmp_path / "t" / "image.tar")
    assert out["source"] == "local" and out["runtime"] == "container"
    assert out["digest"] == "ghcr.io/me/app@sha256:c0ffee"
    assert ["container", "image", "save", "--output", str(tmp_path / "t" / "image.tar"), "--", "ghcr.io/me/app:1"] in fake.calls
    assert not any(c[:2] == ["docker", "save"] for c in fake.calls)


def test_apple_container_pulls_with_its_own_login(monkeypatch, tmp_path):
    fake = _FakeDocker(info_rc=1, inspect_rc=1, container_rc=0)
    monkeypatch.setattr(sources.subprocess, "run", fake.run)
    out = sources.resolve_image("ghcr.io/me/app:1", tmp_path / "t" / "image.tar")
    assert out["source"] == "registry" and ["container", "image", "pull", "--", "ghcr.io/me/app:1"] in fake.calls


def test_forced_runtime(monkeypatch, tmp_path):
    fake = _FakeDocker(info_rc=0, inspect_rc=0, container_rc=0)
    monkeypatch.setattr(sources.subprocess, "run", fake.run)
    monkeypatch.setenv("LAB_HOST_RUNTIME", "container")
    assert sources.host_runtime().name == "container"
    monkeypatch.setenv("LAB_HOST_RUNTIME", "podman")
    with pytest.raises(sources.SourceError):
        sources.host_runtime()


# --- final review of 3925558 ------------------------------------------------


def _git_init(path: Path) -> None:
    subprocess.run(["git", "init", "-q", "-b", "main", str(path)], check=True)


def test_scrub_writes_a_fresh_minimal_config(tmp_path):
    repo = tmp_path / "clone"
    _git_init(repo)
    token = "PLANTEDTOKEN0123456789"
    (repo / ".git" / "config").write_text(
        "[core]\n\tfsmonitor = touch /tmp/pwned-fsmonitor\n\thooksPath = /tmp/evil-hooks\n\tsshCommand = ssh -oProxyCommand=evil\n"
        f'[include]\n\tpath = /tmp/evil.gitconfig\n[includeIf "gitdir:/"]\n\tpath = /tmp/evil2\n'
        f'[url "https://x-access-token:{token}@github.com/"]\n\tinsteadOf = https://github.com/\n'
        "[credential]\n\thelper = store\n"
        f'[remote "origin"]\n\turl = https://u:{token}@github.com/o/r.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n'
        '[branch "main"]\n\tremote = origin\n\tmerge = refs/heads/main\n'
    )
    sources.scrub_git_config(repo)
    config = (repo / ".git" / "config").read_text()
    for gone in ("fsmonitor", "hooksPath", "sshCommand", "include", "insteadOf", "credential", token):
        assert gone not in config, gone
    assert "url = https://github.com/o/r.git" in config
    for path in repo.rglob("*"):
        if path.is_file():
            assert token not in path.read_text(errors="ignore"), path


def test_host_git_calls_disable_hooks_and_fsmonitor():
    opts = " ".join(sources.GIT_SAFE_OPTS)
    assert "core.hooksPath=/dev/null" in opts and "core.fsmonitor=false" in opts


@pytest.mark.parametrize(
    "bad",
    [
        "https://github.com/a/b\nx",
        "https://github.com/a/b\x7f",
        "ssh://-oProxyCommand=x/y",
        "ssh://git@-oX/y",
        "-oX@github.com:a/b",
        "git@-oProxyCommand=x:a/b",
        "owner/repo@--upload-pack=x",
        "owner/repo@-x",
        "https://github.com/a/b@-x",
        "git@github.com:a/b@-x",
        "own_er/repo",
    ],
)
def test_parse_repo_refuses_option_like_and_control_input(bad):
    with pytest.raises(sources.SourceError):
        sources.parse_repo(bad)


def test_detect_stack_refuses_a_manifest_linking_outside(tmp_path):
    outside = tmp_path / "secret.json"
    outside.write_text('{"scripts": {"dev": "x"}}')
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").symlink_to(outside)
    with pytest.raises(sources.SourceError):
        sources.detect_stack(app)
