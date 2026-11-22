"""Command line: ``python -m lab <command>``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, evals, lint, runner, sbx
from . import scope as scope_mod
from .recipe import RecipeError, discover, find
from .sbx import AGENTS


def _add_run_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--scope", metavar="FILE", help="scope file (required for security recipes)")
    parser.add_argument("--agent", choices=sorted(AGENTS), default="claude")
    parser.add_argument("--target", metavar="PATH", help=f"code or files to analyse, mounted read-only at {runner.TARGET_MOUNT}")
    parser.add_argument(
        "--target-repo", metavar="SRC[@REF]", help="git repo (owner/repo, URL, ssh) cloned on the host, then mounted like --target"
    )
    parser.add_argument("--with-submodules", action="store_true", help="clone --target-repo/--target-app repos with submodules")
    parser.add_argument("--pr", metavar="N", type=int, help="check out pull request N of --target-repo")
    parser.add_argument(
        "--target-app", metavar="PATH|SRC[@REF]", help="an app (local folder or repo) installed and started inside the sandbox"
    )
    parser.add_argument("--app-install", metavar="CMD", help="override the detected install command for --target-app")
    parser.add_argument("--app-cmd", metavar="CMD", help="override the detected start command for --target-app")
    parser.add_argument("--app-port", metavar="N", type=int, help="override the detected port for --target-app")
    parser.add_argument("--app-health", metavar="PATH", help="HTTP path polled until --target-app answers (default /)")
    parser.add_argument("--app-env", metavar="FILE", help="dotenv file copied to app/.env; values are redacted from evidence")
    parser.add_argument(
        "--target-image", metavar="REF|TAR", help="docker image ref (saved or pulled on the host) or tarball to load inside the sandbox"
    )
    parser.add_argument(
        "--target-port", metavar="N|HOST:CONTAINER", help="run --target-image as an app on localhost (only with --target-image)"
    )
    parser.add_argument("--target-url", metavar="URL", help="remote app to test; must be http(s) and authorized by --scope")
    parser.add_argument("--acp", action="store_true", help="drive the agent over ACP through burner (burner run --acp)")
    parser.add_argument("--model", metavar="ID", help="model id offered by the agent over ACP (needs --acp)")
    parser.add_argument("--permission", choices=("auto", "ask"), default="auto", help="ACP permissions: auto-allow (logged) or ask")
    parser.add_argument("--dry-run", action="store_true", help="print the plan and run nothing")
    parser.add_argument("--keep", action="store_true", help="keep the sandbox after the run")
    parser.add_argument("--runs-dir", metavar="DIR", type=Path, help="where run directories are created (default: ./runs)")
    parser.add_argument("--prompt", action="append", default=[], metavar="TEXT", help="operator note added to TASK.md (repeatable)")
    parser.add_argument("--prompt-file", action="append", default=[], metavar="FILE", help="operator note read from a file (repeatable)")
    parser.add_argument("--events", metavar="FILE|-", help="write live run events as NDJSON to FILE in the run dir, or to stdout with -")
    parser.add_argument("--answers", metavar="DIR|FIFO", help="operator answer channel for lab-ask questions")
    parser.add_argument(
        "--on-ask",
        metavar="MODE",
        help="what to do when the agent asks: timeout=<dur> (default 30m), skip, or fail (aborts the run, exit 4)",
    )
    parser.add_argument("--yes", action="store_true", help="answer every lab-ask question with skip (non-interactive)")


def _run(recipe_ref: str, args: argparse.Namespace) -> int:
    try:
        recipe = find(recipe_ref)
        operator_notes = [{"source": "prompt", "text": text} for text in args.prompt]
        for note_file in args.prompt_file:
            path = Path(note_file)
            operator_notes.append({"source": f"file:{path.name}", "text": path.read_text(encoding="utf-8")})
        plan = runner.build_plan(
            recipe,
            agent_name=args.agent,
            scope_path=args.scope,
            target=args.target,
            target_repo=args.target_repo,
            with_submodules=args.with_submodules,
            pr=args.pr,
            target_app=args.target_app,
            app_install=args.app_install,
            app_cmd=args.app_cmd,
            app_port=args.app_port,
            app_health=args.app_health,
            app_env=args.app_env,
            target_image=args.target_image,
            target_port=args.target_port,
            target_url=args.target_url,
            runs_dir=args.runs_dir,
            keep=args.keep,
            operator_notes=operator_notes,
            acp=args.acp,
            model=args.model,
            permission=args.permission,
        )
        if args.dry_run:
            print(runner.render_plan(plan))
            return runner.EXIT_OK
        runner.preflight(plan)
        runner.doctor(plan)
        return runner.execute_plan(plan, events=args.events, on_ask=args.on_ask, answers=args.answers, yes=args.yes)
    except RecipeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return runner.EXIT_REFUSED
    except runner.Refused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return exc.code
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return runner.EXIT_REFUSED


def _cmd_list(args: argparse.Namespace) -> int:
    for recipe in discover():
        scope = "scope" if runner.needs_scope(recipe) else "-"
        print(f"{recipe.id:42} {recipe.status:8} {recipe.meta.get('risk', '?'):7} {scope:6} {recipe.meta.get('summary', '')}")
    return 0


def agent_table() -> list[dict]:
    """Every agent the runner can launch: the source of truth for burner."""
    out = []
    for a in sbx.AGENTS.values():
        out.append(
            {
                "name": a.name,
                "secret_service": a.secret_service,
                "setup_commands": list(a.setup_commands),
                "own_workload_ok": bool(a.mixin_kit),
                "acp": getattr(a, "acp", None) or None,
                "login_note": a.interactive_login_note,
            }
        )
    return out


def _cmd_agents(args: argparse.Namespace) -> int:
    table = agent_table()
    if args.json:
        print(json.dumps({"agents": table}, indent=2))
        return 0
    for a in table:
        print(f"{a['name']:<8} secret: {a['secret_service']:<10} setup: {'; '.join(a['setup_commands'])}")
    return 0


def _cmd_lint(args: argparse.Namespace) -> int:
    if args.recipe:
        # Lint the named recipes only; the index is checked by a full run.
        try:
            report = {r.id: lint.lint_recipe(r) for r in (find(ref) for ref in args.recipe)}
        except RecipeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        recipes = len(report)
    else:
        report = lint.lint_all(strict_index=args.strict_index)
        recipes = len(report) - 2
    failed = 0
    for label, errors in report.items():
        if lint.is_failure(errors):
            failed += 1
            print(f"FAIL {label}")
            for error in errors:
                print(f"     - {error}")
        elif errors:
            print(f"warn {label}")
            for error in errors:
                print(f"     - {error}")
        elif args.verbose:
            print(f"ok   {label}")
    print(f"recipe-lint: {recipes} recipe(s), {failed} failing")
    return 1 if failed else 0


def _cmd_eval(args: argparse.Namespace) -> int:
    try:
        recipes = [find(args.recipe)] if args.recipe else [r for r in discover() if not r.is_stub]
    except RecipeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    failed = 0
    for recipe in recipes:
        evidence_dir = (Path(args.run) / "workspace" / "evidence") if args.run else None
        try:
            results = evals.run(recipe, evidence_dir)
        except (FileNotFoundError, ValueError) as exc:
            print(f"FAIL {recipe.id}: {exc}")
            failed += 1
            continue
        bad = [r for r in results if not r.passed]
        failed += bool(bad)
        print(f"{'FAIL' if bad else 'ok  '} {recipe.id} ({len(results) - len(bad)}/{len(results)} checks)")
        for res in results if args.verbose else bad:
            print(f"     {'pass' if res.passed else 'FAIL'} {res.check} [{res.detail}]")
    return 1 if failed else 0


def _cmd_scope(args: argparse.Namespace) -> int:
    try:
        scope = scope_mod.load(args.file, check_dates=not args.ignore_dates)
    except scope_mod.ScopeError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return runner.EXIT_REFUSED
    policy = scope_mod.network_policy(scope)
    print(f"scope {scope.id}: valid {scope.not_before} to {scope.not_after}, mode {scope.mode}")
    print(f"  allow: {', '.join(policy['allow']) or 'nothing'}")
    print(f"  deny:  {', '.join(policy['deny']) or 'nothing extra'}")
    for host in args.host or []:
        print(f"  {host}: {'in scope' if scope.in_scope(host) else 'OUT OF SCOPE'}")
    return 0 if all(scope.in_scope(h) for h in args.host or []) else runner.EXIT_REFUSED


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lab", description="Run disposable lab recipes for coding agents in Docker Sandboxes (sbx).")
    parser.add_argument("--version", action="version", version=f"lab {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="run a recipe in a fresh sandbox")
    p_run.add_argument("recipe", help="category/name, or a unique name")
    _add_run_args(p_run)
    p_run.set_defaults(func=lambda a: _run(a.recipe, a))

    p_list = sub.add_parser("list", help="list recipes")
    p_list.set_defaults(func=_cmd_list)

    p_agents = sub.add_parser("agents", help="list the agents the runner can launch")
    p_agents.add_argument("--json", action="store_true")
    p_agents.set_defaults(func=_cmd_agents)

    p_lint = sub.add_parser("lint", help="validate every recipe against the contract")
    p_lint.add_argument("recipe", nargs="*", help="lint only these recipes (default: everything, including the index)")
    p_lint.add_argument("--strict-index", action="store_true", help="also fail when a recipe has no recipes.yaml entry")
    p_lint.add_argument("-v", "--verbose", action="store_true")
    p_lint.set_defaults(func=_cmd_lint)

    p_eval = sub.add_parser("eval", help="check that a recipe produces its evidence")
    p_eval.add_argument("recipe", nargs="?", help="default: every recipe")
    p_eval.add_argument("--run", metavar="RUN_DIR", help="evaluate a real run instead of the golden fixture")
    p_eval.add_argument("-v", "--verbose", action="store_true")
    p_eval.set_defaults(func=_cmd_eval)

    p_scope = sub.add_parser("scope", help="validate a scope file and show its network policy")
    p_scope.add_argument("file")
    p_scope.add_argument("--host", action="append", help="check whether a host is in scope (repeatable)")
    p_scope.add_argument("--ignore-dates", action="store_true")
    p_scope.set_defaults(func=_cmd_scope)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


def recipe_main(run_py: str, argv: list[str] | None = None) -> int:
    """Entry point for a recipe's own ``run.py``."""
    parser = argparse.ArgumentParser(prog=f"{Path(run_py).parent.name}/run.py", description="Run this recipe with the lab runner.")
    _add_run_args(parser)
    args = parser.parse_args(argv)
    return _run(str(Path(run_py).resolve().parent), args)
