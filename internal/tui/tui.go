// Package tui is burner's interactive mode: pick a recipe, answer only the
// questions that recipe needs, review the plan, run.
package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"

	"github.com/BRYANN2K/sbx-burner/internal/appdetect"
	"github.com/BRYANN2K/sbx-burner/internal/catalog"
	"github.com/BRYANN2K/sbx-burner/internal/doctor"
	"github.com/BRYANN2K/sbx-burner/internal/engine"
	"github.com/BRYANN2K/sbx-burner/internal/live"
)

// ErrAborted is returned when the user leaves the menu.
var ErrAborted = errors.New("aborted")

// Run walks the user from recipe choice to a run. It returns the engine
// exit code.
func Run(ctx context.Context, root string, recipes []catalog.Recipe, checks []doctor.Result) (int, error) {
	runnable := []catalog.Recipe{}
	for _, r := range recipes {
		if r.Runnable() {
			runnable = append(runnable, r)
		}
	}
	if len(runnable) == 0 {
		return 2, errors.New("no runnable recipe in the catalog")
	}

	fmt.Fprintln(os.Stderr, statusLine(checks))
	fmt.Fprintln(os.Stderr, "catalog: "+root)

	var category string
	catOpts := []huh.Option[string]{}
	for _, c := range catalog.Categories(runnable) {
		n := 0
		for _, r := range runnable {
			if catalog.DisplayCategory(r) == c {
				n++
			}
		}
		catOpts = append(catOpts, huh.NewOption(fmt.Sprintf("%-12s %d", c, n), c))
	}
	if err := huh.NewSelect[string]().Title("Category").Options(catOpts...).Value(&category).Run(); err != nil {
		return 130, ErrAborted
	}

	var recipeID string
	recOpts := []huh.Option[string]{}
	byID := map[string]catalog.Recipe{}
	for _, r := range runnable {
		if catalog.DisplayCategory(r) != category {
			continue
		}
		byID[r.ID] = r
		recOpts = append(recOpts, huh.NewOption(fmt.Sprintf("%-22s %s", r.Name, r.Summary), r.ID))
	}
	if err := huh.NewSelect[string]().Title("Recipe").Options(recOpts...).Value(&recipeID).Height(14).Run(); err != nil {
		return 130, ErrAborted
	}
	r := byID[recipeID]

	opts := engine.RunOptions{Recipe: r.EngineRef()}

	if err := askTarget(r, &opts); err != nil {
		return 130, err
	}
	if r.Scope != "none" {
		if err := askScope(r, &opts); err != nil {
			return 130, err
		}
	}
	if err := askAgent(r, checks, &opts); err != nil {
		return 130, err
	}

	var notes string
	if err := huh.NewText().Title("Notes for the agent (optional)").Value(&notes).Run(); err != nil {
		return 130, ErrAborted
	}
	if strings.TrimSpace(notes) != "" {
		opts.Prompts = []string{strings.TrimSpace(notes)}
	}

	// Plan first: the engine prints exactly what it will run.
	plan := opts
	plan.DryRun = true
	fmt.Fprintln(os.Stderr)
	if code, err := engine.Exec(ctx, root, plan.Args()); err != nil || code != 0 {
		return code, err
	}

	run := false
	if err := huh.NewConfirm().Title("Run it?").Affirmative("Run").Negative("Cancel").Value(&run).Run(); err != nil || !run {
		fmt.Fprintln(os.Stderr, "Nothing ran. Same run without the menu:\n  burner "+shellJoin(opts.Args()))
		return 0, nil
	}
	code, _, err := live.Run(ctx, root, opts, live.Options{Out: os.Stderr, Ask: live.Interactive})
	return code, err
}

func askTarget(r catalog.Recipe, o *engine.RunOptions) error {
	if r.TargetMode == "none" && !r.Accepts("demo") {
		return nil
	}
	kinds := []huh.Option[string]{}
	label := map[string]string{
		"app":   "Running project (npm, python, go…)",
		"path":  "Local folder or files",
		"repo":  "GitHub or git repo",
		"image": "Docker image (local or registry)",
		"url":   "URL",
		"demo":  "Demo target",
	}
	order := []string{"app", "path", "repo", "image", "url", "demo"}
	sorted := []string{}
	for _, k := range order {
		if r.Accepts(k) {
			sorted = append(sorted, k)
		}
	}
	for _, k := range sorted {
		if k == "port" {
			continue // asked together with the image
		}
		if l, ok := label[k]; ok {
			kinds = append(kinds, huh.NewOption(l, k))
		}
	}
	if r.Demo != "" && !r.Accepts("demo") {
		kinds = append(kinds, huh.NewOption(label["demo"], "demo"))
	}
	if len(kinds) == 0 {
		return nil
	}
	kind := kinds[0].Value
	if len(kinds) > 1 {
		if err := huh.NewSelect[string]().Title("Where is your target?").Options(kinds...).Value(&kind).Run(); err != nil {
			return ErrAborted
		}
	}
	switch kind {
	case "path":
		v, err := pickPath("Folder or files to test", true, true, nil)
		o.Target = v
		return err
	case "image":
		var how string
		if err := huh.NewSelect[string]().Title("Image").Options(
			huh.NewOption("Image name (local or registry)", "ref"),
			huh.NewOption("Tarball file (docker save / container image save)", "tar"),
		).Value(&how).Run(); err != nil {
			return ErrAborted
		}
		if how == "tar" {
			v, err := pickPath("Image tarball", false, true, []string{".tar", ".tgz", ".gz", ".oci"})
			if err != nil {
				return err
			}
			o.TargetImage = v
		} else if err := input("Image", "ghcr.io/you/app:1.0", &o.TargetImage, nonEmpty); err != nil {
			return err
		}
		if r.Accepts("port") {
			return input("Port (empty to scan the image only)", "8080", &o.TargetPort, nil)
		}
	case "repo":
		return input("Repo", "owner/repo or owner/repo@branch (private repos use your git login)", &o.TargetRepo, nonEmpty)
	case "app":
		var where string
		if err := huh.NewSelect[string]().Title("Project").Options(
			huh.NewOption("Local folder", "local"),
			huh.NewOption("GitHub or git repo", "repo"),
		).Value(&where).Run(); err != nil {
			return ErrAborted
		}
		if where == "local" {
			v, err := pickPath("Project folder", true, false, nil)
			if err != nil {
				return err
			}
			o.TargetApp = v
		} else if err := input("Repo", "owner/repo or owner/repo@branch", &o.TargetApp, nonEmpty); err != nil {
			return err
		}
		if st, err := os.Stat(o.TargetApp); err == nil && st.IsDir() {
			if a, ok := appdetect.Detect(o.TargetApp); ok {
				o.AppInstall, o.AppCmd, o.AppPort = a.Install, a.Start, strconv.Itoa(a.Port)
				fmt.Fprintf(os.Stderr, "Detected %s · install: %s · start: %s · port %d\n", a.Stack, a.Install, a.Start, a.Port)
			}
		}
		if err := input("Start command", "npm run dev", &o.AppCmd, nonEmpty); err != nil {
			return err
		}
		return input("Port", "3000", &o.AppPort, nonEmpty)
	case "url":
		return input("URL", "https://staging.example.com", &o.TargetURL, nonEmpty)
	case "demo":
		o.Demo = true
	}
	return nil
}

func askScope(r catalog.Recipe, o *engine.RunOptions) error {
	title := "Scope file"
	if r.Scope == "optional" {
		title += " (empty to skip)"
	}
	validate := existsFile
	if r.Scope == "optional" {
		validate = func(s string) error {
			if s == "" {
				return nil
			}
			return existsFile(s)
		}
	}
	if r.Scope == "optional" {
		var use bool
		if err := huh.NewConfirm().Title("Use a scope file?").Value(&use).Run(); err != nil {
			return ErrAborted
		}
		if !use {
			return nil
		}
	}
	fmt.Fprintf(os.Stderr, "No scope yet? Copy %s/scope.example.yaml and edit it.\n", r.Dir)
	v, err := pickPath(title, false, true, []string{".yaml", ".yml"})
	if err != nil {
		return err
	}
	if err := validate(v); err != nil {
		return err
	}
	o.Scope = v
	return nil
}

// pickPath offers the folder burner was started in, a file browser, or a
// typed path. dirs/files say what may be picked.
func pickPath(title string, dirs, files bool, types []string) (string, error) {
	cwd, _ := os.Getwd()
	opts := []huh.Option[string]{}
	if dirs {
		opts = append(opts, huh.NewOption("This folder ("+cwd+")", "here"))
	}
	opts = append(opts, huh.NewOption("Browse…", "browse"), huh.NewOption("Type a path", "type"))
	how := opts[0].Value
	if err := huh.NewSelect[string]().Title(title).Options(opts...).Value(&how).Run(); err != nil {
		return "", ErrAborted
	}
	var v string
	switch how {
	case "here":
		return cwd, nil
	case "browse":
		fp := huh.NewFilePicker().Title(title).CurrentDirectory(cwd).DirAllowed(dirs).FileAllowed(files).ShowHidden(false).Height(15).Value(&v)
		if len(types) > 0 {
			fp = fp.AllowedTypes(types)
		}
		if err := fp.Run(); err != nil {
			return "", ErrAborted
		}
	default:
		if err := input(title, "./", &v, existsPath); err != nil {
			return "", err
		}
	}
	v = strings.TrimSpace(v)
	if err := existsPath(v); err != nil {
		return "", fmt.Errorf("%s: %w", v, err)
	}
	return v, nil
}

func askAgent(r catalog.Recipe, checks []doctor.Result, o *engine.RunOptions) error {
	agents := r.Agents
	if len(agents) == 0 {
		agents = []string{"claude", "codex"}
	}
	opts := []huh.Option[string]{}
	for _, a := range agents {
		if _, ok := doctor.AgentServices[a]; !ok {
			continue
		}
		name := map[string]string{"claude": "Claude Code", "codex": "Codex", "devin": "Devin"}[a]
		if !doctor.AgentReady(checks, a) {
			name += " (no credential: " + doctor.AgentServices[a].Fix + ")"
		}
		opts = append(opts, huh.NewOption(name, a))
	}
	if len(opts) == 0 {
		return errors.New("this recipe lists no agent burner supports yet")
	}
	o.Agent = opts[0].Value
	for _, op := range opts {
		if doctor.AgentReady(checks, op.Value) {
			o.Agent = op.Value
			break
		}
	}
	if len(opts) == 1 {
		return nil
	}
	if err := huh.NewSelect[string]().Title("Agent").Options(opts...).Value(&o.Agent).Run(); err != nil {
		return ErrAborted
	}
	return nil
}

func input(title, placeholder string, value *string, validate func(string) error) error {
	in := huh.NewInput().Title(title).Placeholder(placeholder).Value(value)
	if validate != nil {
		in = in.Validate(validate)
	}
	if err := in.Run(); err != nil {
		return ErrAborted
	}
	*value = strings.TrimSpace(*value)
	return nil
}

func nonEmpty(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("required")
	}
	return nil
}

func existsPath(s string) error {
	if _, err := os.Stat(strings.TrimSpace(s)); err != nil {
		return errors.New("not found")
	}
	return nil
}

func existsFile(s string) error {
	st, err := os.Stat(strings.TrimSpace(s))
	if err != nil || st.IsDir() {
		return errors.New("file not found")
	}
	return nil
}

func statusLine(checks []doctor.Result) string {
	parts := []string{}
	for _, c := range checks {
		mark := map[doctor.Level]string{doctor.OK: "ok", doctor.Warn: "!", doctor.Fail: "x"}[c.Level]
		parts = append(parts, strings.TrimSuffix(strings.TrimSuffix(c.Title, " credential"), " installed")+" "+mark)
	}
	return "burner · " + strings.Join(parts, " · ")
}

func shellJoin(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " '\"$`\\*?") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		out[i] = a
	}
	return strings.Join(out, " ")
}
