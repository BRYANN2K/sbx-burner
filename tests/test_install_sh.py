"""install.sh against a fake release served from file:// URLs."""

import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / "install.sh"
TAG = "v1.2.3"
ASSET = "burner_1.2.3_linux_amd64.tar.gz"
TOOLS = [
    "sh", "curl", "tar", "gzip", "awk", "sed", "grep", "head", "mkdir", "mktemp",
    "rm", "cp", "mv", "chmod", "cat", "sha256sum", "shasum", "perl", "dirname", "env",
]  # fmt: skip

pytestmark = pytest.mark.skipif(shutil.which("curl") is None, reason="curl missing")


def _stub(path: Path, body: str) -> None:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)


def _archive(binary: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in (("burner", binary), ("LICENSE", b"Apache-2.0\n")):
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o755
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.fixture
def env(tmp_path):
    """A fake release, a PATH with only the tools install.sh needs, a
    uname stub for linux/amd64, and no cosign unless a test adds one."""
    rel = tmp_path / "download" / TAG
    rel.mkdir(parents=True)
    data = _archive(b"#!/bin/sh\necho burner 1.2.3\n")
    (rel / ASSET).write_bytes(data)
    (rel / "checksums.txt").write_text(f"{hashlib.sha256(data).hexdigest()}  {ASSET}\n")
    (rel / "checksums.txt.sig").write_text("sig\n")
    (rel / "checksums.txt.pem").write_text("pem\n")
    api = tmp_path / "api"
    api.mkdir()
    (api / "latest").write_text(json.dumps({"tag_name": TAG, "assets": []}))

    bin_ = tmp_path / "bin"
    bin_.mkdir()
    for t in TOOLS:
        if found := shutil.which(t):
            (bin_ / t).symlink_to(found)
    _stub(bin_ / "uname", 'case "$1" in -s) echo Linux ;; -m) echo "${FAKE_ARCH:-x86_64}" ;; esac\n')
    e = {
        "PATH": str(bin_),
        "HOME": str(tmp_path / "home"),
        "BURNER_INSTALL_API": (api).as_uri(),
        "BURNER_INSTALL_BASE": (tmp_path / "download").as_uri(),
    }
    return {"env": e, "bin": bin_, "rel": rel, "dest": tmp_path / "dest"}


def _run(env, *args, extra=None):
    e = dict(env["env"], **(extra or {}))
    return subprocess.run(
        ["sh", str(INSTALL), "--dir", str(env["dest"]), *args],
        env=e,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_pinned_version_without_cosign_installs(env):
    r = _run(env, "--version", TAG, "--no-cosign")
    assert r.returncode == 0, r.stderr
    assert "warning: --no-cosign" in r.stderr
    exe = env["dest"] / "burner"
    assert exe.stat().st_mode & 0o777 == 0o755
    assert subprocess.run([str(exe)], capture_output=True, text=True).stdout == "burner 1.2.3\n"
    assert "sha256     ok" in r.stdout
    assert "is not on PATH" in r.stdout
    assert "python3" in r.stdout and "git" in r.stdout and "sbx        missing" in r.stdout
    assert r.stdout.rstrip().endswith("run: burner setup")
    assert not list(env["dest"].glob(".burner-new*"))


def test_latest_with_cosign_checks_the_signer(env, tmp_path):
    log = tmp_path / "cosign.args"
    _stub(env["bin"] / "cosign", f'printf "%s\\n" "$@" > "{log}"\n')
    r = _run(env)
    assert r.returncode == 0, r.stderr
    assert "signature  ok (v1.2.3)" in r.stdout
    args = log.read_text().splitlines()
    assert args[0] == "verify-blob"
    i = args.index("--certificate-identity-regexp")
    assert args[i + 1] == (r"^https://github\.com/BRYANN2K/sbx-burner/\.github/workflows/release\.yml@refs/tags/v")
    assert args[args.index("--certificate-oidc-issuer") + 1] == "https://token.actions.githubusercontent.com"
    assert (env["dest"] / "burner").exists()


def test_installer_identity_matches_burner_update():
    go = (ROOT / "internal/update/update.go").read_text()
    sh = INSTALL.read_text()
    ident = r"^https://github\.com/BRYANN2K/sbx-burner/\.github/workflows/release\.yml@refs/tags/v"
    assert f"const SignerIdentity = `{ident}`" in go
    assert f"identity='{ident}'" in sh


def test_bad_checksum_refuses(env):
    (env["rel"] / "checksums.txt").write_text(f"{'0' * 64}  {ASSET}\n")
    r = _run(env, "--version", TAG, "--no-cosign")
    assert r.returncode != 0
    assert "checksum mismatch" in r.stderr
    assert not (env["dest"] / "burner").exists()


def test_bad_signature_refuses(env):
    _stub(env["bin"] / "cosign", "exit 1\n")
    r = _run(env, "--version", TAG)
    assert r.returncode != 0
    assert "signature check failed" in r.stderr
    assert not (env["dest"] / "burner").exists()


def test_missing_cosign_stops(env):
    r = _run(env, "--version", TAG)
    assert r.returncode != 0
    assert "install cosign (brew install cosign) or rerun with --no-cosign" in r.stderr
    assert not (env["dest"] / "burner").exists()


def test_unsupported_arch_refuses(env):
    r = _run(env, "--no-cosign", extra={"FAKE_ARCH": "riscv64"})
    assert r.returncode != 0
    assert "unsupported architecture: riscv64" in r.stderr


def test_bad_version_refuses(env):
    r = _run(env, "--version", "1.2.3; rm -rf /", "--no-cosign")
    assert r.returncode != 0
    assert "not a release tag" in r.stderr


def test_replaces_an_existing_binary(env):
    env["dest"].mkdir()
    (env["dest"] / "burner").write_text("old\n")
    r = _run(env, "--version", TAG, "--no-cosign", extra={"PATH": env["env"]["PATH"] + os.pathsep + str(env["dest"])})
    assert r.returncode == 0, r.stderr
    assert "echo burner 1.2.3" in (env["dest"] / "burner").read_text()
    assert "is not on PATH" not in r.stdout


def test_truncated_script_does_nothing(env, tmp_path):
    text = INSTALL.read_text()
    cut = tmp_path / "cut.sh"
    cut.write_text(text[: len(text) // 2])
    e = dict(env["env"])
    r = subprocess.run(
        ["sh", str(cut), "--version", TAG, "--no-cosign", "--dir", str(env["dest"])],
        env=e,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert "run: burner setup" not in r.stdout
    assert not env["dest"].exists()


def test_file_urls_only_with_the_test_hook():
    sh = INSTALL.read_text()
    assert "proto='=https'\n" in sh
    assert "--proto-redir '=https'" in sh
    assert sh.rstrip().endswith('main "$@"')
