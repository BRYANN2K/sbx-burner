"""Target sources: repo, app and image resolution.

Everything in this module runs on the HOST, before the sandbox exists, and
uses only the user's own credentials (git, gh, docker): the sandbox receives
a cloned tree or a saved image tarball, never a credential. The runner calls
the pure helpers at plan time and the ``python3 -m lab.sources <action>``
entry points from host steps.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

GIT_SAFE_OPTS = (
    "-c",
    "protocol.allow=never",
    "-c",
    "protocol.https.allow=always",
    "-c",
    "protocol.ssh.allow=always",
    "-c",
    "protocol.git.allow=always",
    # Every host git call on a clone: no hooks, no fsmonitor command.
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.fsmonitor=false",
)
# Never let git ask for a credential: a missing login fails fast and loud.
GIT_QUIET_ENV = {"GIT_TERMINAL_PROMPT": "0", "GIT_PROTOCOL_FROM_USER": "0"}

ECOSYSTEM_HOSTS: dict[str, list[str]] = {
    "npm": ["registry.npmjs.org:443"],
    "pypi": ["pypi.org:443", "files.pythonhosted.org:443"],
    "go": ["proxy.golang.org:443", "sum.golang.org:443"],
    "rubygems": ["rubygems.org:443", "index.rubygems.org:443"],
    "composer": ["repo.packagist.org:443"],
    "crates": ["index.crates.io:443", "static.crates.io:443"],
}

APP_COPY_MAX_FILES = 20000
# Caches and VCS data are not worth copying into the workspace.
APP_COPY_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "vendor", "target", "dist", "__pycache__"}


class SourceError(Exception):
    """A source could not be resolved; the message is shown to the user."""


# --- repo sources -----------------------------------------------------------

_GH_SHORTHAND = re.compile(r"^[A-Za-z0-9-]+/[A-Za-z0-9_.-]+$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_BRANCH = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")
_SCP_FORM = re.compile(r"^(?P<user>[A-Za-z0-9_.-]+)@(?P<host>[A-Za-z0-9_.:-]+):(?P<path>\S+)$")


def scrub_url(url: str) -> str:
    """Remove any userinfo from a URL (``https://u:tok@h/p`` -> ``https://h/p``)."""
    match = re.match(r"^(?P<scheme>[a-z][a-z0-9+.-]*://)(?P<auth>[^/@]+)@(?P<rest>\S+)$", url, re.I)
    if match:
        return f"{match.group('scheme')}{match.group('rest')}"
    return url


def parse_repo(src: str) -> tuple[str, str | None]:
    """Split ``SRC[@REF]`` into a clone URL and an optional ref.

    ``owner/repo`` expands to GitHub https. Credentials are refused: a
    ``user:token@`` userinfo always is, and any userinfo is on a http(s) URL.
    A bare ssh user (``git@host:path`` or ``ssh://git@host/path``) is fine —
    ssh users carry no password.
    """
    if not src or src.startswith("-"):
        raise SourceError(f"--target-repo {src!r}: must not start with '-'")
    if _CONTROL.search(src):
        raise SourceError("--target-repo: control characters are refused")
    if src.startswith(("ext::", "fd::", "file://")):
        raise SourceError(f"--target-repo {src!r}: forbidden transport (a local path goes through --target)")

    if "://" in src:
        scheme, rest = src.split("://", 1)
        if scheme == "http":
            raise SourceError(f"--target-repo {src!r}: plain http is refused; use https or ssh")
        if scheme not in ("https", "ssh", "git"):
            raise SourceError(f"--target-repo {src!r}: scheme {scheme!r} is not cloneable here")
        authority, _, path = rest.partition("/")
        ref = None
        if "@" in path:
            path, _, ref = path.rpartition("@")
            if not ref:
                raise SourceError(f"--target-repo {src!r}: empty ref after '@'")
        if authority.startswith("-") or authority.split("@")[-1].startswith("-"):
            raise SourceError(f"--target-repo {src!r}: a host must not start with '-'")
        if ref is not None and ref.startswith("-"):
            raise SourceError(f"--target-repo {src!r}: a ref must not start with '-'")
        if "@" in authority:
            userinfo, _, hostport = authority.rpartition("@")
            if ":" in userinfo:
                raise SourceError(f"--target-repo {src!r}: URLs must not carry credentials; clone uses your own host git login")
            if scheme != "ssh":
                raise SourceError(f"--target-repo {src!r}: userinfo is only accepted on ssh URLs")
            authority = f"{userinfo}@{hostport}"
        return f"{scheme}://{authority}/{path}", ref

    match = _SCP_FORM.match(src)
    if match:
        if match.group("host").startswith("-"):
            raise SourceError(f"--target-repo {src!r}: a host must not start with '-'")
        path = match.group("path")
        ref = None
        if "@" in path:
            path, _, ref = path.rpartition("@")
            if not ref:
                raise SourceError(f"--target-repo {src!r}: empty ref after '@'")
            if ref.startswith("-"):
                raise SourceError(f"--target-repo {src!r}: a ref must not start with '-'")
        return f"{match.group('user')}@{match.group('host')}:{path}", ref

    base, at, tail = src.rpartition("@")
    ref = tail if at and tail else None
    candidate = base if ref else src
    if at and not tail:
        raise SourceError(f"--target-repo {src!r}: empty ref after '@'")
    if ref is not None and ref.startswith("-"):
        raise SourceError(f"--target-repo {src!r}: a ref must not start with '-'")
    if _GH_SHORTHAND.match(candidate):
        return f"https://github.com/{candidate}.git", ref
    raise SourceError(f"--target-repo {src!r}: use owner/repo, a https:// or ssh URL, or a path via --target")


def _git(argv: list[str], **kw) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, **GIT_QUIET_ENV}
    return subprocess.run(["git", *GIT_SAFE_OPTS, *argv], capture_output=True, text=True, env=env, check=False, **kw)


def scrub_git_config(repo_dir: Path) -> None:
    """Replace ``.git/config`` with a fresh minimal one and drop hooks.

    Filtering lines is not enough: a template or include can carry
    ``core.fsmonitor`` (a command run on the next git op), ``core.hooksPath``,
    ``core.sshCommand``, ``include``/``includeIf`` or a tokenised
    ``[url "https://x:TOKEN@…"]`` section header. Later git ops on the clone
    run on the host, and the tree is mounted into the sandbox, so nothing
    from the original config survives: only the remote (credential-free)
    and the checked-out branch are written back.
    """
    hooks = repo_dir / ".git" / "hooks"
    if hooks.is_dir():
        for hook in hooks.iterdir():
            if hook.is_file() and not hook.name.endswith(".sample"):
                hook.unlink()
    git_dir = repo_dir / ".git"
    if not git_dir.is_dir():
        return
    origin = _git(["-C", str(repo_dir), "config", "--file", str(git_dir / "config"), "--get", "remote.origin.url"])
    remote = scrub_url(origin.stdout.strip()) if origin.returncode == 0 else ""
    branch = _git(["-C", str(repo_dir), "symbolic-ref", "--short", "-q", "HEAD"]).stdout.strip()
    lines = [
        "[core]",
        "\trepositoryformatversion = 0",
        "\tfilemode = true",
        "\tbare = false",
        "\tlogallrefupdates = true",
    ]
    if remote and not _CONTROL.search(remote) and '"' not in remote:
        lines += ['[remote "origin"]', f"\turl = {remote}", "\tfetch = +refs/heads/*:refs/remotes/origin/*"]
        if branch and _BRANCH.match(branch):
            lines += [f'[branch "{branch}"]', "\tremote = origin", f"\tmerge = refs/heads/{branch}"]
    (git_dir / "config").write_text("\n".join(lines) + "\n", encoding="utf-8")


def clone_repo(src: str, dest: Path, *, ref: str | None = None, pr: int | None = None, submodules: bool = False) -> dict:
    """Clone on the host with the user's own credentials, then scrub them."""
    url, parsed_ref = parse_repo(src)
    ref = ref if ref is not None else parsed_ref
    if ref and ref.startswith("-"):
        raise SourceError(f"--target-repo ref {ref!r}: must not start with '-'")
    if dest.exists():
        raise SourceError(f"clone destination already exists: {dest}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    argv = ["clone", "--quiet"]
    if submodules:
        argv.append("--recurse-submodules")
    proc = _git([*argv, "--", url, str(dest)])
    if proc.returncode != 0:
        raise SourceError(
            f"git clone {url} failed ({proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else 'exit ' + str(proc.returncode)}); "
            "the repo needs credentials on the host (gh auth, ssh-agent or a credential helper)"
        )
    base = None
    if pr is not None:
        proc = _git(["-C", str(dest), "fetch", "--quiet", "origin", f"+pull/{pr}/head:pr-{pr}"])
        if proc.returncode != 0:
            raise SourceError(f"fetching pull/{pr}/head failed: {proc.stderr.strip()}")
        base = "origin/HEAD"
        ref = f"pr-{pr}"
    if ref:
        proc = _git(["-C", str(dest), "checkout", "--quiet", ref])
        if proc.returncode != 0:
            raise SourceError(f"checkout {ref!r} failed: {proc.stderr.strip()}")
    scrub_git_config(dest)
    return repo_identity(dest, url=url, ref=ref, pr=pr, base=base)


def repo_identity(
    repo_dir: Path, *, url: str | None = None, ref: str | None = None, pr: int | None = None, base: str | None = None
) -> dict:
    """Commit SHA and the credential-free URL for ``run.target``."""
    head = _git(["-C", str(repo_dir), "rev-parse", "HEAD"])
    if head.returncode != 0:
        raise SourceError(f"cannot resolve HEAD in {repo_dir}: {head.stderr.strip()}")
    origin = _git(["-C", str(repo_dir), "config", "--get", "remote.origin.url"])
    remote = scrub_url(origin.stdout.strip()) if origin.returncode == 0 else None
    identity: dict = {"repo": scrub_url(url or remote or ""), "commit": head.stdout.strip()}
    if ref:
        identity["ref"] = ref
    if pr is not None:
        identity["pr"] = pr
    if base:
        identity["base"] = base
    return identity


# --- app sources ------------------------------------------------------------


def parse_env_file(path: Path) -> dict[str, str]:
    """``KEY=value`` lines from a dotenv file; comments and blanks skipped."""
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().removeprefix("export").strip()
        values[key] = value.strip().strip("'\"")
    return values


def _node_stack(app_dir: Path, env: dict[str, str]) -> dict | None:
    pkg = app_dir / "package.json"
    if not pkg.is_file():
        return None
    try:
        data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        data = {}
    scripts = data.get("scripts") or {}
    if (app_dir / "pnpm-lock.yaml").is_file():
        manager, install = "pnpm", "pnpm install"
    elif (app_dir / "yarn.lock").is_file():
        manager, install = "yarn", "yarn install"
    else:
        manager = "npm"
        install = "npm ci" if (app_dir / "package-lock.json").is_file() else "npm install"
    script = "dev" if "dev" in scripts else "start" if "start" in scripts else None
    cmd = f"{manager} run {script}" if script == "dev" else (f"{manager} start" if script else None)
    port = None
    if script and scripts.get(script):
        flag = re.search(r"(?:--port[=\s]|-p\s?)(\d+)", str(scripts[script]))
        if flag:
            port = int(flag.group(1))
    if port is None and env.get("PORT", "").isdigit():
        port = int(env["PORT"])
    if port is None:
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        port = 5173 if "vite" in deps else 4200 if "@angular/core" in deps else 3000
    return {"ecosystem": "npm", "manager": manager, "install": install, "cmd": cmd, "port": port, "health": "/"}


def _python_stack(app_dir: Path, env: dict[str, str]) -> dict | None:
    pyproject = app_dir / "pyproject.toml"
    requirements = app_dir / "requirements.txt"
    if not pyproject.is_file() and not requirements.is_file():
        return None
    text = ""
    for f in (requirements, pyproject):
        if f.is_file():
            text += f.read_text(encoding="utf-8", errors="replace").lower()
    install = "pip install -r requirements.txt" if requirements.is_file() else "pip install ."
    cmd = None
    if (app_dir / "manage.py").is_file() or "django" in text:
        cmd, port = "python manage.py runserver 0.0.0.0:8000", 8000
    elif "fastapi" in text or "uvicorn" in text:
        module = "main" if (app_dir / "main.py").is_file() else "app" if (app_dir / "app.py").is_file() else "main"
        cmd, port = f"uvicorn {module}:app --host 0.0.0.0 --port 8000", 8000
    elif "flask" in text:
        cmd, port = "flask --app app run --host 0.0.0.0 --port 5000", 5000
    elif "gunicorn" in text:
        cmd, port = "gunicorn app:app --bind 0.0.0.0:8000", 8000
    if cmd is None:
        cmd, port = "python -m http.server 8000 --bind 0.0.0.0", 8000
    if env.get("PORT", "").isdigit():
        port = int(env["PORT"])
    return {"ecosystem": "pypi", "manager": "pip", "install": install, "cmd": cmd, "port": port, "health": "/"}


def _outside_link(app_dir: Path, name: str) -> bool:
    """True when ``name`` is a symlink resolving outside ``app_dir``."""
    path = app_dir / name
    if not path.is_symlink():
        return False
    try:
        path.resolve().relative_to(app_dir.resolve())
        return False
    except (ValueError, OSError):
        return True


MANIFESTS = ("package.json", "requirements.txt", "pyproject.toml", "go.mod", "Gemfile", "composer.json", "Cargo.toml", ".env")


def detect_stack(app_dir: Path, env: dict[str, str] | None = None) -> dict | None:
    """Detect the app stack from files only; never executes project code.

    Manifests that are symlinks pointing outside the project are refused:
    the host must not read files the project does not contain.
    """
    env = env or {}
    for name in MANIFESTS:
        if _outside_link(app_dir, name):
            raise SourceError(f"{name} in the app folder links outside it; refused")
    for probe in (_node_stack, _python_stack):
        found = probe(app_dir, env)
        if found:
            break
    if not found:
        if (app_dir / "go.mod").is_file():
            found = {"ecosystem": "go", "manager": "go", "install": "go mod download", "cmd": "go run .", "port": 8080, "health": "/"}
        elif (app_dir / "Gemfile").is_file():
            cmd = None
            gemfile = (app_dir / "Gemfile").read_text(encoding="utf-8", errors="replace").lower()
            if (app_dir / "bin" / "rails").is_file() or "rails" in gemfile:
                cmd = "bin/rails server -b 0.0.0.0 -p 3000"
            found = {"ecosystem": "rubygems", "manager": "bundle", "install": "bundle install", "cmd": cmd, "port": 3000, "health": "/"}
        elif (app_dir / "composer.json").is_file():
            cmd = "php artisan serve --host 0.0.0.0 --port 8000" if (app_dir / "artisan").is_file() else None
            found = {"ecosystem": "composer", "manager": "composer", "install": "composer install", "cmd": cmd, "port": 8000, "health": "/"}
        elif (app_dir / "Cargo.toml").is_file():
            found = {"ecosystem": "crates", "manager": "cargo", "install": "cargo fetch", "cmd": "cargo run", "port": 8080, "health": "/"}
    if found and env.get("PORT", "").isdigit():
        found["port"] = int(env["PORT"])
    return found


def ecosystem_hosts(ecosystem: str | None) -> list[str]:
    return list(ECOSYSTEM_HOSTS.get(ecosystem or "", []))


def all_ecosystem_hosts() -> list[str]:
    return [host for hosts in ECOSYSTEM_HOSTS.values() for host in hosts]


def _check_no_outside_link(app_dir: Path) -> None:
    for p in app_dir.rglob("*"):
        if p.is_symlink():
            target = p.resolve()
            try:
                target.relative_to(app_dir.resolve())
            except ValueError:
                raise SourceError(f"symlink {p.relative_to(app_dir)} points outside the source tree ({target}); refusing to copy") from None


def copy_app(src: Path, dst: Path) -> int:
    """Copy the app without following symlinks; never touches ``src``."""
    if dst.exists():
        raise SourceError(f"app destination already exists: {dst}")
    _check_no_outside_link(src)
    count = 0

    def ignore(directory: str, names: list[str]) -> set[str]:
        skipped = set()
        for name in names:
            p = Path(directory) / name
            if p.is_dir() and not p.is_symlink() and name in APP_COPY_SKIP_DIRS:
                skipped.add(name)
        return skipped

    for _root, _dirs, files in os.walk(src):
        count += len(files)
    if count > APP_COPY_MAX_FILES:
        raise SourceError(f"{src}: {count} files is above the {APP_COPY_MAX_FILES}-file app copy cap")
    shutil.copytree(src, dst, symlinks=True, ignore=ignore)
    return count


def write_app_scripts(work_dir: Path, stack: dict) -> None:
    """Render ``.lab/app-install.sh`` and ``.lab/app-start.sh`` for the sandbox."""
    lab = work_dir / ".lab"
    lab.mkdir(exist_ok=True)
    install = stack.get("install") or "true"
    (lab / "app-install.sh").write_text(
        "#!/usr/bin/env bash\n# Rendered by the runner from the detected stack.\nset -euo pipefail\ncd app\n" + install + "\n",
        encoding="utf-8",
    )
    cmd = stack["cmd"]
    (lab / "app-start.sh").write_text(
        "#!/usr/bin/env bash\n# Rendered by the runner from the detected stack.\nset -euo pipefail\n"
        + "cd app\n"
        + "if [ -f .env ]; then set -a; . ./.env; set +a; fi\n"
        + f"mkdir -p ../.lab\nnohup bash -c {shlex.quote(cmd)} > ../.lab/app.log 2>&1 & echo $! > ../.lab/app.pid\n"
        + 'echo "app started: pid $(cat ../.lab/app.pid), log .lab/app.log"\n',
        encoding="utf-8",
    )


def prepare_app(
    src: Path,
    work_dir: Path,
    *,
    install: str | None,
    cmd: str | None,
    port: int | None,
    health: str | None,
    env_file: Path | None,
) -> dict:
    """Copy the source into the workspace, detect the stack, render scripts."""
    app_dest = work_dir / "app"
    files = copy_app(src, app_dest)
    env = parse_env_file(env_file) if env_file else {}
    stack = detect_stack(app_dest, env) or {"ecosystem": None, "install": None, "cmd": None, "port": port, "health": "/"}
    for key, value in (("install", install), ("cmd", cmd), ("port", port), ("health", health)):
        if value is not None:
            stack[key] = value
    if not stack.get("cmd"):
        raise SourceError(
            "could not determine how to start the app; pass --app-cmd CMD and --app-port N "
            "(compose files are not supported yet: no --target-compose)"
        )
    stack.setdefault("health", "/")
    if stack.get("port") is None:
        stack["port"] = port
    if env_file:
        shutil.copy2(env_file, app_dest / ".env")
        stack["env_keys"] = sorted(env)
    stack["files"] = files
    lab = work_dir / ".lab"
    lab.mkdir(exist_ok=True)
    (lab / "app.json").write_text(json.dumps(stack, indent=2) + "\n", encoding="utf-8")
    write_app_scripts(work_dir, stack)
    return stack


# --- image sources ----------------------------------------------------------


def _docker_config_auths() -> set[str]:
    """Registry NAMES the user is logged into; never reads or prints tokens."""
    config = Path.home() / ".docker" / "config.json"
    if not config.is_file():
        return set()
    try:
        data = json.loads(config.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return set()
    names = set((data.get("auths") or {}).keys()) | set((data.get("credHelpers") or {}).keys())
    return {n.replace("https://", "").replace("http://", "").split("/")[0] for n in names}


def _registry_of(ref: str) -> str:
    first = ref.split("/", 1)[0] if "/" in ref else ""
    return first if ("." in first or ":" in first or first == "localhost") else "docker.io"


def resolve_image(ref: str, out_tar: Path, *, source_file: Path | None = None, identity_file: Path | None = None) -> dict:
    """Save ``ref`` to a tarball, preferring the host's own daemon.

    Order: local ``docker save``, host ``docker pull`` + save, or - when the
    host has no daemon and the ref looks public - source ``registry-sandbox``
    so the sandbox pulls it through install_allow itself. Registry credentials
    never leave the host.
    """
    out_tar.parent.mkdir(parents=True, exist_ok=True)
    result: dict = {"ref": ref}

    def finish(source: str, digest: str | None = None) -> dict:
        result["source"] = source
        if digest:
            result["digest"] = digest
        if source_file:
            source_file.parent.mkdir(parents=True, exist_ok=True)
            source_file.write_text(json.dumps({"source": source, "ref": ref, "digest": digest}, indent=2) + "\n", encoding="utf-8")
        if identity_file:
            identity_file.parent.mkdir(parents=True, exist_ok=True)
            identity = {k: v for k, v in result.items() if v}
            identity_file.write_text(json.dumps(identity, indent=2) + "\n", encoding="utf-8")
        return result

    rt = host_runtime()
    if rt is None:
        registry = _registry_of(ref)
        if registry in _registry_logins() or registry not in ("docker.io", "index.docker.io", "ghcr.io", "registry-1.docker.io"):
            raise SourceError(
                f"no container runtime on the host and {registry} looks private: "
                "start Docker (or colima) or Apple container (`container system start`), or pass a tarball to --target-image"
            )
        return finish("registry-sandbox")
    result["runtime"] = rt.name

    digest = rt.inspect_digest(ref)
    if digest is not None:
        rt.save(ref, out_tar)
        return finish("local", digest or None)

    rt.pull(ref)
    digest = rt.inspect_digest(ref)
    rt.save(ref, out_tar)
    return finish("registry", digest or None)


# --- host container runtimes ----------------------------------------------


class HostRuntime:
    """A host container runtime used to save local images and to pull with
    the user's own registry login. Implementations: Docker (incl. colima)
    and Apple container. Nothing here runs inside the sandbox."""

    name = ""

    def available(self) -> bool:
        raise NotImplementedError

    def inspect_digest(self, ref: str) -> str | None:
        """``repo@sha256:…`` (or an id) when the image is local, else None."""
        raise NotImplementedError

    def save(self, ref: str, out_tar: Path) -> None:
        raise NotImplementedError

    def pull(self, ref: str) -> None:
        raise NotImplementedError


def _run(argv: list[str], timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=False, timeout=timeout)


def _last(proc: subprocess.CompletedProcess[str]) -> str:
    err = proc.stderr.strip()
    return err.splitlines()[-1] if err else f"exit {proc.returncode}"


class DockerRuntime(HostRuntime):
    name = "docker"
    INSPECT = "{{if .RepoDigests}}{{index .RepoDigests 0}}{{else}}{{.Id}}{{end}}"

    def available(self) -> bool:
        return shutil.which("docker") is not None and _run(["docker", "info"], timeout=60).returncode == 0

    def inspect_digest(self, ref: str) -> str | None:
        proc = _run(["docker", "image", "inspect", "--format", self.INSPECT, "--", ref])
        return proc.stdout.strip() if proc.returncode == 0 else None

    def save(self, ref: str, out_tar: Path) -> None:
        proc = _run(["docker", "save", "-o", str(out_tar), "--", ref])
        if proc.returncode != 0:
            raise SourceError(f"docker save {ref} failed: {_last(proc)}")

    def pull(self, ref: str) -> None:
        proc = _run(["docker", "pull", "--", ref])
        if proc.returncode != 0:
            raise SourceError(f"docker pull {ref} failed on the host ({_last(proc)}); check `docker login` for private registries")


class AppleContainerRuntime(HostRuntime):
    """Apple's `container` CLI (macOS). Saves OCI archives; `docker load` in
    the sandbox reads them."""

    name = "container"

    def available(self) -> bool:
        return shutil.which("container") is not None and _run(["container", "system", "status"], timeout=60).returncode == 0

    def inspect_digest(self, ref: str) -> str | None:
        proc = _run(["container", "image", "inspect", "--", ref])
        if proc.returncode != 0:
            return None
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return ""
        item = data[0] if isinstance(data, list) and data else data
        conf = item.get("configuration", {}) if isinstance(item, dict) else {}
        digest = (conf.get("descriptor") or {}).get("digest")
        name = conf.get("name") or ref
        return f"{name.split('@')[0].rsplit(':', 1)[0] if ':' in name.split('/')[-1] else name}@{digest}" if digest else ""

    def save(self, ref: str, out_tar: Path) -> None:
        proc = _run(["container", "image", "save", "--output", str(out_tar), "--", ref])
        if proc.returncode != 0:
            raise SourceError(f"container image save {ref} failed: {_last(proc)}")

    def pull(self, ref: str) -> None:
        proc = _run(["container", "image", "pull", "--", ref])
        if proc.returncode != 0:
            raise SourceError(
                f"container image pull {ref} failed on the host ({_last(proc)}); check `container registry login` for private registries"
            )


RUNTIMES: dict[str, type[HostRuntime]] = {"docker": DockerRuntime, "container": AppleContainerRuntime}


def host_runtime() -> HostRuntime | None:
    """The runtime from $LAB_HOST_RUNTIME (docker | container), else the first
    one that answers: Docker, then Apple container. None when neither does."""
    forced = os.environ.get("LAB_HOST_RUNTIME", "").strip()
    if forced:
        if forced not in RUNTIMES:
            raise SourceError(f"LAB_HOST_RUNTIME={forced!r}: use docker or container")
        rt = RUNTIMES[forced]()
        if not rt.available():
            raise SourceError(f"LAB_HOST_RUNTIME={forced} is not running on this host")
        return rt
    for cls in (DockerRuntime, AppleContainerRuntime):
        rt = cls()
        if rt.available():
            return rt
    return None


def _registry_logins() -> set[str]:
    """Registry names the user is logged into, for Docker and Apple container."""
    names = _docker_config_auths()
    if shutil.which("container"):
        proc = _run(["container", "registry", "list"], timeout=30)
        if proc.returncode == 0:
            for line in proc.stdout.splitlines()[1:]:
                host = line.split()[0] if line.split() else ""
                if host:
                    names.add(host)
    return names


# --- host CLI ---------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lab.sources", description="Host-side target source actions for the lab runner.")
    sub = parser.add_subparsers(dest="action", required=True)

    p_clone = sub.add_parser("clone", help="clone a repo with the host's own credentials")
    p_clone.add_argument("src")
    p_clone.add_argument("dest", type=Path)
    p_clone.add_argument("--ref")
    p_clone.add_argument("--pr", type=int)
    p_clone.add_argument("--submodules", action="store_true")
    p_clone.add_argument("--identity", type=Path)

    p_ident = sub.add_parser("repo-identity", help="write the clone identity JSON")
    p_ident.add_argument("src_dir", type=Path)
    p_ident.add_argument("out", type=Path)

    p_app = sub.add_parser("prepare-app", help="copy an app source into the workspace and render its scripts")
    p_app.add_argument("src_dir", type=Path)
    p_app.add_argument("work_dir", type=Path)
    p_app.add_argument("--install")
    p_app.add_argument("--cmd")
    p_app.add_argument("--port", type=int)
    p_app.add_argument("--health")
    p_app.add_argument("--env", type=Path)

    sub.add_parser("host-runtime", help="print the host container runtime burner will use (docker | container | none)")
    p_img = sub.add_parser("resolve-image", help="save an image ref to a tarball via the host runtime (Docker or Apple container)")
    p_img.add_argument("ref")
    p_img.add_argument("out_tar", type=Path)
    p_img.add_argument("--source-file", type=Path)
    p_img.add_argument("--identity", type=Path)

    args = parser.parse_args(argv)
    try:
        if args.action == "clone":
            identity = clone_repo(args.src, args.dest, ref=args.ref, pr=args.pr, submodules=args.submodules)
            if args.identity:
                args.identity.parent.mkdir(parents=True, exist_ok=True)
                args.identity.write_text(json.dumps(identity, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(identity))
        elif args.action == "repo-identity":
            identity = repo_identity(args.src_dir)
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(identity, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(identity))
        elif args.action == "prepare-app":
            stack = prepare_app(
                args.src_dir, args.work_dir, install=args.install, cmd=args.cmd, port=args.port, health=args.health, env_file=args.env
            )
            summary = {k: v for k, v in stack.items() if k != "env_keys"}
            summary["env_keys"] = stack.get("env_keys", [])
            print(json.dumps(summary))
        elif args.action == "host-runtime":
            rt = host_runtime()
            print(rt.name if rt else "none")
        elif args.action == "resolve-image":
            print(json.dumps(resolve_image(args.ref, args.out_tar, source_file=args.source_file, identity_file=args.identity)))
    except SourceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
