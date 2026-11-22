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
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/BRYANN2K/sbx-burner/internal/acp"
	"github.com/BRYANN2K/sbx-burner/internal/catalog"
	"github.com/BRYANN2K/sbx-burner/internal/doctor"
	"github.com/BRYANN2K/sbx-burner/internal/engine"
	"github.com/BRYANN2K/sbx-burner/internal/events"
	"github.com/BRYANN2K/sbx-burner/internal/live"
	"github.com/BRYANN2K/sbx-burner/internal/mcp"
	"github.com/BRYANN2K/sbx-burner/internal/scaffold"
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
  burner                      interactive menu
  burner list [--json]        recipes in the catalog and in ~/.burner/recipes
  burner show <recipe> [--json]
  burner run <recipe> [flags] run a recipe (same flags as the menu asks)
  burner new <category>/<name>
  burner lint [recipe...]     check recipes against the contract
  burner agents [--json]      the agents the runner can launch
  burner eval [recipe]        check a recipe produces its evidence
  burner scope <file> [--host H]
  burner doctor [--json]
  burner answer <run-dir> <ask-id> <answer>   answer the agent from another terminal
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
  --demo  --scope FILE  --agent NAME (burner agents)  --dry-run  --keep  --runs-dir DIR
  --prompt TEXT  --prompt-file FILE   notes for the agent (repeatable)
  --on-ask skip|fail|timeout=30m      when nobody answers the agent
  --acp   drive the agent over ACP (live permissions, model choice, follow-up notes)
      --model ID  --permission auto|ask    auto = allow inside the sandbox, every decision logged
  --yes   never prompt; fail with exit 3 when something is missing; questions are skipped
  --json  run: events as NDJSON on stdout
  --json  machine-readable output (list, show, doctor)

Exit codes: 0 ok · 1 internal error · 2 usage or refused · 3 not ready · 4 run failed · 5 evidence gate failed

Global:
  --catalog DIR   recipe catalog checkout (default: this repo, $BURNER_CATALOG, ~/.burner/catalog)
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	catalogFlag, args := extractFlag(args, "--catalog")
	if len(args) == 0 {
		if !isTerminal(os.Stdin) || !isTerminal(os.Stdout) {
			fmt.Fprint(stderr, usage)
			return exitUsage
		}
		return interactive(ctx, catalogFlag, stderr)
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
		return cmdDoctor(ctx, rest, stdout)
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
	case "update":
		return cmdUpdate(ctx, rest, stdout, stderr)
	case "catalog":
		return cmdCatalog(ctx, rest, stdout, stderr)
	case "mcp":
		return cmdMCP(ctx, catalogFlag, stderr)
	case "models":
		return cmdModels(rest, stdout, stderr)
	case "acp":
		return cmdACP(rest, stdout, stderr)
	case "acp-bridge":
		return cmdACPBridge(rest, stderr)
	case "lint", "eval", "scope", "agents":
		root, err := catalog.FindRoot(catalogFlag)
		if err != nil {
			return fail(stderr, exitNotReady, err)
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

func interactive(ctx context.Context, catalogFlag string, stderr io.Writer) int {
	root, err := catalog.FindRoot(catalogFlag)
	if err != nil {
		return fail(stderr, exitNotReady, err)
	}
	recipes, problems := catalog.Load(root)
	for _, p := range problems {
		fmt.Fprintln(stderr, "warning:", p)
	}
	out, err := tui.Run(ctx, tui.Config{Root: root, Recipes: recipes, Version: version})
	if errors.Is(err, tui.ErrAborted) {
		return exitOK
	}
	if err != nil {
		return fail(stderr, exitFailed, err)
	}
	switch out.Action {
	case "update":
		return cmdUpdate(ctx, nil, os.Stdout, stderr)
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

func cmdDoctor(ctx context.Context, args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	if fs.Parse(args) != nil {
		return exitUsage
	}
	home, _ := os.UserHomeDir()
	results := doctor.Check(ctx, doctor.Options{DiskPath: home})
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
	fs.BoolVar(&o.Demo, "demo", false, "")
	fs.BoolVar(&o.DryRun, "dry-run", false, "")
	fs.BoolVar(&o.Keep, "keep", false, "")
	fs.StringVar(&o.RunsDir, "runs-dir", "", "")
	fs.BoolVar(&o.ACP, "acp", false, "")
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
	code, st, err := live.Run(ctx, root, o, live.Options{Out: out, JSON: *asJSON, Ask: asker})
	if errors.Is(err, engine.ErrCleanupTimeout) {
		fmt.Fprintln(stderr, leftoverHint(st))
		return exitFailed
	}
	if err != nil {
		return fail(stderr, exitFailed, err)
	}
	if o.ACP && st != nil && st.Done != nil && st.Done.Report != "" {
		cacheModels(filepath.Join(filepath.Dir(st.Done.Report), acp.ModelsFile))
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
			case "demo":
				kinds = append(kinds, "--demo")
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
func absPaths(cmd string, args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = a
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

// reorder lets flags come after the positional argument (`run x --demo`).
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
