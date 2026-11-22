// Command burner runs disposable lab recipes for coding agents in Docker
// Sandboxes (sbx). With no arguments it opens the interactive menu; every
// menu action also has a flag form for scripts and agents.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/BRYANN2K/sbx-burner/internal/acp"
	"github.com/BRYANN2K/sbx-burner/internal/catalog"
	"github.com/BRYANN2K/sbx-burner/internal/doctor"
	"github.com/BRYANN2K/sbx-burner/internal/engine"
	"github.com/BRYANN2K/sbx-burner/internal/events"
	"github.com/BRYANN2K/sbx-burner/internal/live"
	"github.com/BRYANN2K/sbx-burner/internal/mcp"
	"github.com/BRYANN2K/sbx-burner/internal/sandboxes"
	"github.com/BRYANN2K/sbx-burner/internal/scaffold"
	"github.com/BRYANN2K/sbx-burner/internal/series"
	"github.com/BRYANN2K/sbx-burner/internal/tui"
	"github.com/BRYANN2K/sbx-burner/internal/update"
)

// Set by the release build (-ldflags "-X main.version=...").
var version = "dev"

// Exit codes, shared with the engine so agents read one table:
//
//	0 ok · 1 internal error · 2 usage or refused · 3 not ready (preflight,
//	missing input, doctor failure) · 4 run failed · 5 evidence gate failed.
//
// burner passes the engine's code through unchanged.
const (
	exitOK       = 0
	exitFailed   = 1
	exitUsage    = 2
	exitNotReady = 3
)

const usage = `burner — disposable lab recipes for coding agents in sbx

Usage:
  burner                      interactive menu (setup on the first launch)
  burner setup                machine, agents, approvals, preferences, a first run
  burner list [--json]        recipes in the catalog and in ~/.burner/recipes
  burner show <recipe> [--json]
  burner run <recipe> [flags] run a recipe (same flags as the menu asks)
  burner new <category>/<name>
  burner lint [recipe...]     check recipes against the contract
  burner agents [--json]      the agents the runner can launch
  burner eval [recipe]        check a recipe produces its evidence
  burner scope <file> [--host H] [--json]
  burner scope edit <file>      open the scope form on a scope file
  burner scope new <recipe> --target-... [--owner N] [--auth own-lab|written --reference REF] [--days 30] [--out PATH] [--dry-run] [--json]
                              write a scope for that recipe from the target (~/.burner/scopes)
  burner doctor [--json]
  burner answer <run-dir> <ask-id> <answer>   answer the agent from another terminal
  burner series list            saved series
  burner series run NAME [--target…|--target-app…|--target-url…] [--scope FILE]
                              run a saved series against one target, combined report
  burner sandboxes [--json]   sandboxes kept with --keep
  burner burn NAME|--kept     remove a kept sandbox, or all of them
  burner approve --agent A    approve the agent's credential for lab kits (interactive)
  burner update [--check] [--install]   update recipe catalogs; check (or install) a new burner
  burner catalog add <git-url> [--name N] | list
  burner mcp                  MCP server on stdio (limits in ~/.burner/mcp.yaml)
  burner acp agents [--json]  agents burner can drive over ACP
  burner models --agent A [--json]   models the agent offered on its last ACP run
  burner version

Run flags (targets):
  --target PATH              local folder or files, mounted read-only
  --target-repo SRC[@REF]    GitHub/git repo, cloned on this machine with your git login
  --target-app PATH|SRC      project started inside the sandbox (npm, python, go, rails, php, rust)
      --app-install CMD --app-cmd CMD --app-port N --app-health PATH --app-env FILE
  --target-image REF|TAR     local Docker image, registry image or docker save tarball
      --target-port N        run the image as an app on localhost:N
  --target-url URL           remote app listed in the scope file
  --with-submodules
Run flags (other):
  --scope FILE  --agent NAME (burner agents)  --dry-run  --keep  --runs-dir DIR
  --prompt TEXT  --prompt-file FILE   notes for the agent (repeatable)
  --on-ask skip|fail|timeout=30m      when nobody answers the agent
  --interactive  open the agent's own TUI in the sandbox with the task sent; the run goes on when you quit it
  --acp   drive the agent over ACP (live permissions, model choice, follow-up notes)
      --model ID  --permission auto|ask    auto = allow inside the sandbox, every decision logged
  --yes   never prompt; fail with exit 3 when something is missing; questions are skipped
  --json  run: events as NDJSON on stdout
  --json  machine-readable output (list, show, doctor)

Exit codes: 0 ok · 1 internal error · 2 usage or refused · 3 not ready · 4 run failed · 5 evidence gate failed

Global:
  --catalog DIR   recipe catalog checkout (default: this repo, $BURNER_CATALOG, ~/.burner/catalog)
`

// needsCatalog lists the commands that read the recipe catalog.
func needsCatalog(cmd string) bool {
	switch cmd {
	case "list", "show", "run", "new", "series", "setup", "approve", "mcp", "doctor", "lint", "eval", "scope", "agents":
		return true
	}
	return false
}

// ensureCatalog clones the official catalog into ~/.burner/catalog on first
// use, so a fresh install works without a separate `burner update`. It does
// nothing when --catalog or $BURNER_CATALOG is set, or a catalog exists.
func ensureCatalog(ctx context.Context, catalogFlag string, stderr io.Writer) {
	if catalogFlag != "" || os.Getenv("BURNER_CATALOG") != "" {
		return
	}
	home := catalog.Home()
	if home == "" {
		return
	}
	if root, err := catalog.FindRoot(""); err == nil {
		refreshCatalog(ctx, root, home, stderr)
		return
	}
	fmt.Fprintln(stderr, "fetching the recipe catalog into "+filepath.Join(home, "catalog")+" …")
	if _, err := update.EnsureOfficial(ctx, home); err != nil {
		fmt.Fprintln(stderr, "burner: could not fetch the recipe catalog:", err)
	}
}

// refreshCatalog fast-forwards the official catalog at most once an hour, so
// kits and recipes stay in step with the release without a separate
// `burner update`. It never overwrites local edits (fast-forward only) and
// stays quiet when offline.
func refreshCatalog(ctx context.Context, root, home string, stderr io.Writer) {
	if !catalog.IsOfficial(root) {
		return
	}
	stamp := filepath.Join(home, "cache", "catalog-fetched")
	if st, err := os.Stat(stamp); err == nil && time.Since(st.ModTime()) < time.Hour {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	c, err := update.Pull(ctx, root)
	_ = os.MkdirAll(filepath.Dir(stamp), 0o700)
	_ = os.WriteFile(stamp, nil, 0o600)
	if err == nil && c.From != c.To {
		fmt.Fprintf(stderr, "recipe catalog updated: %s → %s\n", c.From, c.To)
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	catalogFlag, args := extractFlag(args, "--catalog")
	if len(args) == 0 || needsCatalog(args[0]) {
		ensureCatalog(ctx, catalogFlag, stderr)
	}
	if len(args) == 0 {
		if !isTerminal(os.Stdin) || !isTerminal(os.Stdout) {
			fmt.Fprint(stderr, usage)
			return exitUsage
		}
		return interactive(ctx, catalogFlag, stderr, false)
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return exitOK
	case "version", "--version":
		fmt.Fprintln(stdout, "burner", version)
		return exitOK
	case "doctor":
		return cmdDoctor(ctx, catalogFlag, rest, stdout)
	case "list":
		return cmdList(catalogFlag, rest, stdout, stderr)
	case "show":
		return cmdShow(catalogFlag, rest, stdout, stderr)
	case "run":
		return cmdRun(ctx, catalogFlag, rest, stderr)
	case "new":
		return cmdNew(catalogFlag, rest, stdout, stderr)
	case "answer":
		return cmdAnswer(rest, stderr)
	case "series":
		return cmdSeries(ctx, catalogFlag, rest, stdout, stderr)
	case "setup":
		if !isTerminal(os.Stdin) || !isTerminal(os.Stdout) {
			return fail(stderr, exitUsage, errors.New("burner setup is interactive: it needs a terminal"))
		}
		return interactive(ctx, catalogFlag, stderr, true)
	case "sandboxes":
		return cmdSandboxes(ctx, rest, stdout, stderr)
	case "burn":
		return cmdBurn(ctx, rest, stdout, stderr)
	case "approve":
		return cmdApprove(ctx, catalogFlag, rest, stderr)
	case "update":
		return cmdUpdate(ctx, rest, stdout, stderr)
	case "catalog":
		return cmdCatalog(ctx, rest, stdout, stderr)
	case "mcp":
		return cmdMCP(ctx, catalogFlag, stderr)
	case "models":
		return cmdModels(ctx, catalogFlag, rest, stdout, stderr)
	case "acp":
		return cmdACP(rest, stdout, stderr)
	case "acp-bridge":
		return cmdACPBridge(rest, stderr)
	case "lint", "eval", "scope", "agents":
		root, err := catalog.FindRoot(catalogFlag)
		if err != nil {
			return fail(stderr, exitNotReady, err)
		}
		if cmd == "scope" && len(rest) == 2 && rest[0] == "edit" {
			if !isTerminal(os.Stdin) || !isTerminal(os.Stdout) {
				return fail(stderr, exitUsage, errors.New("burner scope edit opens the scope form: it needs a terminal"))
			}
			out, err := tui.RunScopeEdit(ctx, tui.Config{Root: root, Version: version}, rest[1])
			if err != nil {
				return fail(stderr, exitFailed, err)
			}
			if out.Action == "scope-saved" {
				fmt.Fprintln(stderr, "saved "+out.Report)
			}
			return out.Code
		}
		if cmd == "scope" && len(rest) > 1 && rest[0] == "new" {
			rest = scopeNewArgs(root, rest)
		}
		code, err := engine.Exec(ctx, root, append([]string{cmd}, absPaths(cmd, rest)...))
		if err != nil {
			return fail(stderr, exitFailed, err)
		}
		return code
	default:
		fmt.Fprintf(stderr, "burner: unknown command %q\n\n%s", cmd, usage)
		return exitUsage
	}
}

func interactive(ctx context.Context, catalogFlag string, stderr io.Writer, setup bool) int {
	root, err := catalog.FindRoot(catalogFlag)
	if err != nil {
		return fail(stderr, exitNotReady, err)
	}
	recipes, problems := catalog.Load(root)
	for _, p := range problems {
		fmt.Fprintln(stderr, "warning:", p)
	}
	_, configured := tui.LoadPrefs()
	out, err := tui.Run(ctx, tui.Config{Root: root, Recipes: recipes, Version: version, Setup: setup || !configured, Official: catalog.IsOfficial(root), Release: newerRelease})
	if errors.Is(err, tui.ErrAborted) {
		return exitOK
	}
	if err != nil {
		return fail(stderr, exitFailed, err)
	}
	switch out.Action {
	case "update":
		return cmdUpdate(ctx, nil, os.Stdout, stderr)
	case "update-install":
		return cmdUpdate(ctx, []string{"--install"}, os.Stdout, stderr)
	case "left-while-stopping":
		fmt.Fprintln(stderr, "burner: you left while the runner was destroying the sandbox. It keeps going in the background; check with: sbx ls (remove a leftover with: sbx rm --force <name>)")
	}
	if out.Report != "" {
		fmt.Fprintln(stderr, "report: "+out.Report)
	}
	if out.Command != "" {
		fmt.Fprintln(stderr, "same run without the menu: "+out.Command)
	}
	return out.Code
}

func cmdDoctor(ctx context.Context, catalogFlag string, args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	if fs.Parse(args) != nil {
		return exitUsage
	}
	home, _ := os.UserHomeDir()
	results := doctor.Check(ctx, doctor.Options{DiskPath: home})
	if root, err := catalog.FindRoot(catalogFlag); err == nil {
		if rows, err := engine.Approvals(ctx, root); err == nil {
			results = append(results, doctor.ApprovalResults(rows)...)
		}
	}
	if *asJSON {
		_ = json.NewEncoder(stdout).Encode(map[string]any{"status": doctor.Worst(results), "checks": results})
	} else {
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		for _, r := range results {
			mark := map[doctor.Level]string{doctor.OK: "ok", doctor.Warn: "!", doctor.Fail: "x"}[r.Level]
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", mark, r.Title, r.Detail, r.Fix)
		}
		tw.Flush()
	}
	if doctor.Worst(results) == doctor.Fail {
		return exitNotReady
	}
	return exitOK
}

func cmdList(catalogFlag string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	if fs.Parse(args) != nil {
		return exitUsage
	}
	root, err := catalog.FindRoot(catalogFlag)
	if err != nil && !errors.Is(err, catalog.ErrNoCatalog) {
		return fail(stderr, exitFailed, err)
	}
	recipes, problems := catalog.Load(root)
	for _, p := range problems {
		fmt.Fprintln(stderr, "warning:", p)
	}
	runnable := recipes[:0:0]
	for _, r := range recipes {
		if r.Runnable() {
			runnable = append(runnable, r)
		}
	}
	if *asJSON {
		_ = json.NewEncoder(stdout).Encode(runnable)
		return exitOK
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	for _, r := range runnable {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", displayID(r), strings.Join(r.Targets, ","), r.Summary)
	}
	tw.Flush()
	return exitOK
}

func cmdShow(catalogFlag string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	if fs.Parse(reorder(args)) != nil || fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: burner show <recipe> [--json]")
		return exitUsage
	}
	r, code := findRecipe(catalogFlag, fs.Arg(0), stderr)
	if code != exitOK {
		return code
	}
	if *asJSON {
		_ = json.NewEncoder(stdout).Encode(r)
		return exitOK
	}
	tested := "not yet"
	if len(r.TestedWith) > 0 {
		tested = strings.Join(r.TestedWith, ", ")
	}
	fmt.Fprintf(stdout, "%s\n%s\n\ntarget   %s (%s)\nscope    %s\nrisk     %s\ntime     %s\ntested   %s\nimage    %s\n",
		displayID(r), r.Summary, strings.Join(r.Targets, ", "), r.TargetMode, r.Scope, r.Risk, r.Time, tested, r.Image)
	return exitOK
}

func cmdRun(ctx context.Context, catalogFlag string, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o engine.RunOptions
	fs.StringVar(&o.Scope, "scope", "", "")
	fs.StringVar(&o.Agent, "agent", "claude", "")
	fs.StringVar(&o.Target, "target", "", "")
	fs.StringVar(&o.TargetImage, "target-image", "", "")
	fs.StringVar(&o.TargetPort, "target-port", "", "")
	fs.StringVar(&o.TargetURL, "target-url", "", "")
	fs.StringVar(&o.TargetRepo, "target-repo", "", "")
	fs.StringVar(&o.TargetApp, "target-app", "", "")
	fs.StringVar(&o.AppInstall, "app-install", "", "")
	fs.StringVar(&o.AppCmd, "app-cmd", "", "")
	fs.StringVar(&o.AppPort, "app-port", "", "")
	fs.StringVar(&o.AppHealth, "app-health", "", "")
	fs.StringVar(&o.AppEnv, "app-env", "", "")
	fs.BoolVar(&o.Submodules, "with-submodules", false, "")
	fs.Func("prompt", "", func(v string) error { o.Prompts = append(o.Prompts, v); return nil })
	fs.Func("prompt-file", "", func(v string) error { o.PromptFiles = append(o.PromptFiles, v); return nil })
	fs.StringVar(&o.OnAsk, "on-ask", "", "")
	fs.BoolVar(&o.DryRun, "dry-run", false, "")
	fs.BoolVar(&o.Keep, "keep", false, "")
	fs.StringVar(&o.RunsDir, "runs-dir", "", "")
	fs.BoolVar(&o.ACP, "acp", false, "")
	fs.BoolVar(&o.Interactive, "interactive", false, "")
	fs.StringVar(&o.Model, "model", "", "")
	fs.StringVar(&o.Permission, "permission", "", "")
	yes := fs.Bool("yes", false, "")
	asJSON := fs.Bool("json", false, "")
	if fs.Parse(reorder(args)) != nil || fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: burner run <recipe> [flags]")
		return exitUsage
	}
	r, code := findRecipe(catalogFlag, fs.Arg(0), stderr)
	if code != exitOK {
		return code
	}
	if !r.Runnable() {
		return fail(stderr, exitUsage, fmt.Errorf("%s is not available yet", r.ID))
	}
	// Agent mode: refuse early, with the missing input named, instead of
	// letting the engine prompt or guess.
	if missing := missingInputs(r, o); len(missing) > 0 && *yes {
		return fail(stderr, exitNotReady, fmt.Errorf("%s needs: %s", r.ID, strings.Join(missing, ", ")))
	}
	o.Recipe = r.EngineRef()
	root, err := catalog.FindRoot(catalogFlag)
	if err != nil {
		return fail(stderr, exitNotReady, err)
	}
	fmt.Fprintln(stderr, "catalog:", root)
	if o.DryRun {
		var code int
		if *yes {
			code, err = engine.ExecStreams(ctx, root, o.Args(), nil, os.Stdout, stderr)
		} else {
			code, err = engine.Exec(ctx, root, o.Args())
		}
		if err != nil {
			return fail(stderr, exitFailed, err)
		}
		return code
	}
	if o.Interactive && !o.DryRun && (*yes || *asJSON || !isTerminal(os.Stdin) || !isTerminal(os.Stdout)) {
		return fail(stderr, exitUsage, errors.New("--interactive opens the agent's own TUI: it needs a terminal, without --yes or --json"))
	}
	if *yes && o.OnAsk == "" {
		o.OnAsk = "skip" // nobody is there to answer
	}
	var asker live.Asker
	if !*yes && !*asJSON && isTerminal(os.Stdin) {
		asker = live.Interactive
	}
	out := stderr
	if *asJSON {
		out = os.Stdout
	}
	var handoff func([]string) error
	if o.Interactive {
		handoff = runOnTerminal
	}
	code, st, err := live.Run(ctx, root, o, live.Options{Out: out, JSON: *asJSON, Ask: asker, Handoff: handoff})
	if errors.Is(err, engine.ErrCleanupTimeout) {
		fmt.Fprintln(stderr, leftoverHint(st))
		return exitFailed
	}
	if err != nil {
		return fail(stderr, exitFailed, err)
	}
	if o.Keep && st != nil && st.RunID != "" {
		recordKept(st.RunID, o, r.ID)
	}
	if o.ACP && st != nil && st.Done != nil && st.Done.Report != "" {
		cacheModels(filepath.Join(filepath.Dir(st.Done.Report), acp.ModelsFile))
	}
	return code
}

func cmdApprove(ctx context.Context, catalogFlag string, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	agent := fs.String("agent", "", "")
	if fs.Parse(args) != nil || *agent == "" {
		fmt.Fprintln(stderr, "usage: burner approve --agent <name>")
		return exitUsage
	}
	root, err := catalog.FindRoot(catalogFlag)
	if err != nil {
		return fail(stderr, exitNotReady, err)
	}
	code, err := engine.Exec(ctx, root, []string{"approve", "--agent", *agent})
	if err != nil {
		return fail(stderr, exitFailed, err)
	}
	return code
}

func cmdAnswer(args []string, stderr io.Writer) int {
	if len(args) != 3 {
		fmt.Fprintln(stderr, "usage: burner answer <run-dir> <ask-id> <answer>")
		return exitUsage
	}
	if err := events.Answer(filepath.Join(args[0], "control.sock"), args[1], args[2]); err != nil {
		return fail(stderr, exitFailed, err)
	}
	return exitOK
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// missingInputs lists what the recipe requires and the flags do not give.
func missingInputs(r catalog.Recipe, o engine.RunOptions) []string {
	var missing []string
	if r.TargetMode == "required" && !o.HasTarget() {
		kinds := []string{}
		for _, k := range r.Targets {
			switch k {
			case "path":
				kinds = append(kinds, "--target")
			case "repo":
				kinds = append(kinds, "--target-repo")
			case "app":
				kinds = append(kinds, "--target-app")
			case "image":
				kinds = append(kinds, "--target-image")
			case "url":
				kinds = append(kinds, "--target-url")
			}
		}
		missing = append(missing, "a target ("+strings.Join(kinds, " | ")+")")
	}
	if r.Scope == "required" && o.Scope == "" {
		missing = append(missing, "--scope")
	}
	return missing
}

func cmdNew(catalogFlag string, args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || !strings.Contains(args[0], "/") {
		fmt.Fprintf(stderr, "usage: burner new <category>/<name>\ncategories: %s\n", strings.Join(scaffold.Categories, ", "))
		return exitUsage
	}
	root, err := catalog.FindRoot(catalogFlag)
	if err != nil {
		return fail(stderr, exitNotReady, err)
	}
	category, name, _ := strings.Cut(args[0], "/")
	dest, err := scaffold.New(filepath.Join(root, "template"), catalog.UserRecipesDir(), category, name)
	if err != nil {
		return fail(stderr, exitUsage, err)
	}
	fmt.Fprintf(stdout, "Created %s\nNext: edit RECIPE.md, recipe.yaml and AGENTS.md, then run: burner lint %s\n", dest, dest)
	return exitOK
}

// newerRelease is the TUI's release check: the latest tag when it is
// newer than this binary, else "".
func newerRelease(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rel, err := update.Latest(ctx)
	if err != nil || !update.Newer(rel.Tag, version) {
		return "", err
	}
	return rel.Tag, nil
}

func cmdUpdate(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	check := fs.Bool("check", false, "")
	install := fs.Bool("install", false, "")
	if fs.Parse(args) != nil {
		return exitUsage
	}
	home := catalog.Home()
	if !*check {
		if _, err := update.EnsureOfficial(ctx, home); err != nil {
			fmt.Fprintln(stderr, "warning:", err)
		}
		for _, dir := range update.Catalogs(home) {
			c, err := update.Pull(ctx, dir)
			if err != nil {
				fmt.Fprintln(stderr, "warning:", err)
				continue
			}
			switch {
			case c.From == c.To:
				fmt.Fprintf(stdout, "%s: up to date (%s)\n", c.Catalog, c.To)
			default:
				fmt.Fprintf(stdout, "%s: %s → %s · %d new · %d updated\n", c.Catalog, c.From, c.To, len(c.Added), len(c.Updated))
				for _, id := range c.Added {
					fmt.Fprintln(stdout, "  + "+id)
				}
				for _, id := range c.Updated {
					fmt.Fprintln(stdout, "  ~ "+id)
				}
			}
		}
	}
	rel, err := update.Latest(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "burner: release check skipped:", err)
		return exitOK
	}
	if update.Newer(rel.Tag, version) {
		exe, _ := os.Executable()
		exe, _ = filepath.EvalSymlinks(exe)
		switch {
		case strings.Contains(exe, "/Cellar/") || strings.Contains(exe, "/homebrew/"):
			fmt.Fprintf(stdout, "burner %s is available: brew upgrade burner\n", rel.Tag)
		case !*install:
			fmt.Fprintf(stdout, "burner %s is available: burner update --install\n", rel.Tag)
		default:
			dir, err := os.MkdirTemp("", "burner-update-")
			if err != nil {
				return fail(stderr, exitFailed, err)
			}
			defer os.RemoveAll(dir)
			archive, err := update.Download(ctx, rel, dir)
			if err != nil {
				return fail(stderr, exitFailed, err)
			}
			if err := update.Install(archive, exe); err != nil {
				return fail(stderr, exitFailed, err)
			}
			fmt.Fprintf(stdout, "burner updated to %s (signature and checksum verified)\n", rel.Tag)
		}
	} else {
		fmt.Fprintf(stdout, "burner %s is the latest\n", version)
	}
	return exitOK
}

func cmdCatalog(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: burner catalog add <git-url> [--name N] | list")
		return exitUsage
	}
	home := catalog.Home()
	switch args[0] {
	case "list":
		for _, dir := range update.Catalogs(home) {
			fmt.Fprintln(stdout, dir)
		}
		return exitOK
	case "add":
		fs := flag.NewFlagSet("catalog add", flag.ContinueOnError)
		name := fs.String("name", "", "")
		if fs.Parse(reorder(args[1:])) != nil || fs.NArg() != 1 {
			fmt.Fprintln(stderr, "usage: burner catalog add <git-url> [--name N]")
			return exitUsage
		}
		dest, err := update.AddCatalog(ctx, home, fs.Arg(0), *name)
		if err != nil {
			return fail(stderr, exitFailed, err)
		}
		fmt.Fprintln(stdout, "Added", dest)
		fmt.Fprintln(stderr, "warning: team catalogs are not signed yet. Their recipes run on this machine: add only repositories you trust.")
		return exitOK
	}
	fmt.Fprintln(stderr, "usage: burner catalog add <git-url> [--name N] | list")
	return exitUsage
}

func cmdMCP(ctx context.Context, catalogFlag string, stderr io.Writer) int {
	root, err := catalog.FindRoot(catalogFlag)
	if err != nil {
		return fail(stderr, exitNotReady, err)
	}
	home := catalog.Home()
	cfg, err := mcp.LoadConfig(home)
	if err != nil {
		return fail(stderr, exitUsage, err)
	}
	s := &mcp.Server{Root: root, Home: home, Config: cfg, Client: mcp.ClientToken(), Version: version}
	if err := s.Serve(ctx, os.Stdin, os.Stdout); err != nil {
		return fail(stderr, exitFailed, err)
	}
	return exitOK
}

func findRecipe(catalogFlag, ref string, stderr io.Writer) (catalog.Recipe, int) {
	root, err := catalog.FindRoot(catalogFlag)
	if err != nil && !errors.Is(err, catalog.ErrNoCatalog) {
		return catalog.Recipe{}, fail(stderr, exitFailed, err)
	}
	recipes, _ := catalog.Load(root)
	r, err := catalog.Find(recipes, ref)
	if err != nil {
		return r, fail(stderr, exitUsage, err)
	}
	return r, exitOK
}

func displayID(r catalog.Recipe) string {
	switch r.Source {
	case catalog.User:
		return "mine/" + r.Name
	case catalog.Team:
		return filepath.Base(filepath.Dir(filepath.Dir(filepath.Dir(r.Dir)))) + ":" + r.ID
	}
	return r.ID
}

// absPaths turns path arguments absolute: the engine runs in the catalog root.
// scopeNewArgs resolves the recipe of `scope new` like `run` does, so user
// and team recipes work too.
func scopeNewArgs(root string, rest []string) []string {
	recipes, _ := catalog.Load(root)
	out := append([]string{}, rest...)
	for i := 1; i < len(out); i++ {
		if strings.HasPrefix(out[i], "-") {
			if !strings.Contains(out[i], "=") && out[i] != "--dry-run" && out[i] != "--json" {
				i++ // skip the flag's value
			}
			continue
		}
		if r, err := catalog.Find(recipes, out[i]); err == nil {
			out[i] = r.EngineRef()
		}
		break
	}
	return out
}

func absPaths(cmd string, args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = a
		if i > 0 && args[i-1] == "--out" {
			// The engine runs in the catalog root: a new output path must
			// still land where the user is.
			if abs, err := filepath.Abs(a); err == nil {
				out[i] = abs
			}
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		if _, err := os.Stat(a); err == nil {
			if abs, err := filepath.Abs(a); err == nil {
				out[i] = abs
			}
		}
	}
	return out
}

// reorder lets flags come after the positional argument (`run x --target .`).
func reorder(args []string) []string {
	var flags, pos []string
	valueFlags := map[string]bool{"--prompt": true, "--prompt-file": true, "--on-ask": true, "--name": true, "--scope": true, "--agent": true, "--target": true, "--target-image": true, "--target-port": true, "--target-url": true, "--runs-dir": true,
		"--target-repo": true, "--target-app": true, "--app-install": true, "--app-cmd": true, "--app-port": true, "--app-health": true, "--app-env": true, "--model": true, "--permission": true}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			if valueFlags[a] && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}

// extractFlag removes `--name value` or `--name=value` from args.
func extractFlag(args []string, name string) (string, []string) {
	var value string
	out := []string{}
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == name && i+1 < len(args):
			value = args[i+1]
			i++
		case strings.HasPrefix(args[i], name+"="):
			value = strings.TrimPrefix(args[i], name+"=")
		default:
			out = append(out, args[i])
		}
	}
	return value, out
}

func fail(stderr io.Writer, code int, err error) int {
	fmt.Fprintln(stderr, "burner:", err)
	return code
}

// leftoverHint tells the user how to remove a sandbox the engine could not
// destroy before it was stopped.
func leftoverHint(st *live.State) string {
	name := ""
	if st != nil {
		name = engine.SandboxName(st.RunID)
	}
	if name == "" {
		return "burner: the run was stopped before its cleanup finished; a sandbox may remain: sbx ls, then sbx rm --force <name>"
	}
	return fmt.Sprintf("burner: the run was stopped before its cleanup finished; the sandbox may remain: sbx ls, then sbx rm --force %s", name)
}

// runOnTerminal runs a checked handoff command (sbx exec -it …) with the
// user's terminal attached.
func runOnTerminal(argv []string) error {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// sbxLister and sbxRemover talk to sbx; tests replace them.
var (
	sbxLister  sandboxes.Lister  = sandboxes.SbxList
	sbxRemover sandboxes.Remover = sandboxes.SbxRemove
)

// recordKept remembers a sandbox kept with --keep, so `burner sandboxes`
// lists it and `burner burn` may remove it.
func recordKept(runID string, o engine.RunOptions, recipe string) {
	name := events.SandboxForRun(runID)
	runs := o.RunsDir
	if runs == "" {
		cwd, _ := os.Getwd()
		runs = filepath.Join(cwd, "runs")
	}
	_ = sandboxes.Add(catalog.Home(), sandboxes.Entry{Name: name, RunDir: filepath.Join(runs, runID), Recipe: recipe, Agent: o.Agent, Created: time.Now()})
}

func cmdSandboxes(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	asJSON := len(args) == 1 && args[0] == "--json"
	if len(args) > 1 || (len(args) == 1 && !asJSON) {
		fmt.Fprintln(stderr, "usage: burner sandboxes [--json]")
		return exitUsage
	}
	kept, err := sandboxes.List(ctx, catalog.Home(), sbxLister)
	if err != nil {
		return fail(stderr, exitNotReady, err)
	}
	if asJSON {
		if kept == nil {
			kept = []sandboxes.Kept{}
		}
		_ = json.NewEncoder(stdout).Encode(map[string]any{"sandboxes": kept})
		return exitOK
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tRECIPE\tAGENT\tAGE\tSTATE")
	for _, k := range kept {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", k.Name, k.Recipe, k.Agent, sandboxes.Age(k.Created, time.Now()), k.State)
	}
	tw.Flush()
	return exitOK
}

func cmdBurn(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: burner burn NAME|--kept")
		return exitUsage
	}
	home := catalog.Home()
	names := []string{args[0]}
	if args[0] == "--kept" {
		kept, err := sandboxes.List(ctx, home, sbxLister)
		if err != nil {
			return fail(stderr, exitNotReady, err)
		}
		names = nil
		for _, k := range kept {
			names = append(names, k.Name)
		}
	}
	code := exitOK
	for _, n := range names {
		if err := sandboxes.Burn(ctx, home, n, sbxRemover); err != nil {
			fmt.Fprintln(stderr, "burner:", err)
			code = exitFailed
			continue
		}
		fmt.Fprintln(stdout, "burned "+n)
	}
	return code
}

func cmdSeries(ctx context.Context, catalogFlag string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "list" && args[0] != "run") {
		fmt.Fprintln(stderr, "usage: burner series list | burner series run NAME [target flags] [--scope FILE]")
		return exitUsage
	}
	home := catalog.Home()
	if args[0] == "list" {
		for _, s := range series.List(home) {
			var ids []string
			for _, it := range s.Items {
				ids = append(ids, it.Recipe)
			}
			fmt.Fprintf(stdout, "%-24s %s\n", s.Name, strings.Join(ids, ", "))
		}
		return exitOK
	}
	fs := flag.NewFlagSet("series run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o engine.RunOptions
	fs.StringVar(&o.Target, "target", "", "")
	fs.StringVar(&o.TargetRepo, "target-repo", "", "")
	fs.StringVar(&o.TargetApp, "target-app", "", "")
	fs.StringVar(&o.AppCmd, "app-cmd", "", "")
	fs.StringVar(&o.AppPort, "app-port", "", "")
	fs.StringVar(&o.TargetImage, "target-image", "", "")
	fs.StringVar(&o.TargetPort, "target-port", "", "")
	fs.StringVar(&o.TargetURL, "target-url", "", "")
	fs.StringVar(&o.Scope, "scope", "", "")
	fs.StringVar(&o.RunsDir, "runs-dir", "", "")
	if fs.Parse(reorder(args[1:])) != nil || fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: burner series run NAME [target flags] [--scope FILE]")
		return exitUsage
	}
	s, err := series.Load(home, fs.Arg(0))
	if err != nil {
		return fail(stderr, exitUsage, err)
	}
	root, err := catalog.FindRoot(catalogFlag)
	if err != nil {
		return fail(stderr, exitNotReady, err)
	}
	recipes, _ := catalog.Load(root)
	if o.RunsDir == "" {
		cwd, _ := os.Getwd()
		o.RunsDir = filepath.Join(cwd, "runs")
	}
	acpAgents := make([]string, 0, len(acp.Profiles))
	for n := range acp.Profiles {
		acpAgents = append(acpAgents, n)
	}
	plans := series.Prepare(s, recipes, o, acpAgents)
	run := func(ctx context.Context, ro engine.RunOptions) (string, int, error) {
		code, st, err := live.Run(ctx, root, ro, live.Options{Out: stderr})
		report := ""
		if st != nil && st.Done != nil {
			report = st.Done.Report
		}
		return report, code, err
	}
	progress := func(i int, r series.RecipeResult) {
		if r.Status != "running" {
			fmt.Fprintf(stdout, "%d  %-30s %-8s %s %s\n", i+1, r.Recipe, r.Agent, r.Status, r.Reason)
		}
	}
	c, path, err := series.Run(ctx, s, plans, targetLabel(o), o.RunsDir, run, progress)
	if err != nil {
		return fail(stderr, exitFailed, err)
	}
	fmt.Fprintf(stdout, "%d findings · %s\n", len(c.Findings), path)
	for _, r := range c.Recipes {
		if r.Status == "failed" {
			return exitFailed
		}
	}
	return exitOK
}

func targetLabel(o engine.RunOptions) string {
	for _, v := range []string{o.TargetURL, o.TargetApp, o.TargetImage, o.TargetRepo, o.Target} {
		if v != "" {
			return v
		}
	}
	return ""
}
