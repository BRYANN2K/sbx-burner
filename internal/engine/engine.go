// Package engine runs recipes. Until the Go port of the runner lands (with
// parity tests against the Python runner), burner drives the reference
// engine: `python3 -m lab` in the catalog checkout. The flags are the same.
package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// RunOptions mirrors `python -m lab run` flags.
type RunOptions struct {
	Recipe      string
	Scope       string
	Agent       string
	Target      string
	TargetImage string
	TargetPort  string
	TargetURL   string
	TargetRepo  string // owner/repo, https or ssh git URL, optional @ref
	TargetApp   string // local project folder or repo, started in the sandbox
	AppInstall  string
	AppCmd      string
	AppPort     string
	AppHealth   string
	AppEnv      string
	Submodules  bool
	Prompts     []string // operator notes, appended to the task
	PromptFiles []string
	Events      string // "-" for NDJSON on stdout
	OnAsk       string // skip | fail | timeout=DURATION
	Demo        bool
	DryRun      bool
	Keep        bool
	RunsDir     string
}

// Args builds the engine argv for a run (without the python prefix).
func (o RunOptions) Args() []string {
	args := []string{"run", o.Recipe}
	// --flag=value so a value starting with "-" is never read as a flag.
	add := func(flag, v string) {
		if v != "" {
			args = append(args, flag+"="+v)
		}
	}
	add("--scope", abs(o.Scope))
	add("--agent", o.Agent)
	add("--target", abs(o.Target))
	add("--target-image", imageArg(o.TargetImage))
	add("--target-port", o.TargetPort)
	add("--target-url", o.TargetURL)
	add("--target-repo", o.TargetRepo)
	add("--target-app", localOrRemote(o.TargetApp))
	add("--app-install", o.AppInstall)
	add("--app-cmd", o.AppCmd)
	add("--app-port", o.AppPort)
	add("--app-health", o.AppHealth)
	add("--app-env", abs(o.AppEnv))
	for _, p := range o.Prompts {
		add("--prompt", p)
	}
	for _, f := range o.PromptFiles {
		add("--prompt-file", abs(f))
	}
	add("--events", o.Events)
	add("--on-ask", o.OnAsk)
	if o.Submodules {
		args = append(args, "--with-submodules")
	}
	// Runs land where the user is, not inside the catalog checkout.
	runs := o.RunsDir
	if runs == "" {
		if cwd, err := os.Getwd(); err == nil {
			runs = filepath.Join(cwd, "runs")
		}
	}
	add("--runs-dir", abs(runs))
	if o.Demo {
		args = append(args, "--demo")
	}
	if o.DryRun {
		args = append(args, "--dry-run")
	}
	if o.Keep {
		args = append(args, "--keep")
	}
	return args
}

// Python finds a Python 3.11+ interpreter.
func Python() (string, error) {
	if p := os.Getenv("BURNER_PYTHON"); p != "" {
		return p, nil
	}
	for _, name := range []string{"python3.13", "python3.12", "python3.11", "python3"} {
		if p, err := exec.LookPath(name); err == nil {
			out, err := exec.Command(p, "-c", "import sys; print(sys.version_info >= (3, 11))").Output()
			if err == nil && string(out) == "True\n" {
				return p, nil
			}
		}
	}
	return "", errors.New("Python 3.11+ not found (the recipe engine needs it until the Go engine ships)")
}

// bootstrap imports the engine from the catalog root only: -I drops the
// user's site-packages, PYTHON* variables and the cwd from sys.path.
const bootstrap = `import runpy, sys
root = sys.argv.pop(1)
sys.path.insert(0, root)
sys.argv[0] = "lab"
runpy.run_module("lab", run_name="__main__", alter_sys=True)`

// Exec runs the engine (`lab <args>`) in the catalog root with the user's
// terminal attached. -I keeps the user's site-packages and cwd out of it.
func Exec(ctx context.Context, root string, args []string) (int, error) {
	return run(ctx, root, args, os.Stdin, os.Stdout, os.Stderr)
}

// ExecStreams runs the engine with explicit streams.
func ExecStreams(ctx context.Context, root string, args []string, in io.Reader, out, errw io.Writer) (int, error) {
	return run(ctx, root, args, in, out, errw)
}

// ExecTo runs the engine without a terminal: no stdin, output to w.
func ExecTo(ctx context.Context, root string, args []string, w io.Writer) (int, error) {
	return run(ctx, root, args, nil, w, w)
}

func run(ctx context.Context, root string, args []string, in io.Reader, out, errw io.Writer) (int, error) {
	py, err := Python()
	if err != nil {
		return 2, err
	}
	cmd := exec.CommandContext(ctx, py, append([]string{"-I", "-c", bootstrap, root}, args...)...)
	cmd.Dir = root
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, errw
	err = cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	if err != nil {
		return 2, fmt.Errorf("engine: %w", err)
	}
	return 0, nil
}

// abs makes user paths absolute because the engine runs in the catalog root.
func abs(p string) string {
	if p == "" {
		return ""
	}
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

// localOrRemote makes an existing local folder absolute, leaves repos alone.
func localOrRemote(v string) string {
	if v == "" {
		return ""
	}
	if st, err := os.Stat(v); err == nil && st.IsDir() {
		return abs(v)
	}
	return v
}

// HasTarget reports whether any target was given.
func (o RunOptions) HasTarget() bool {
	return o.Target != "" || o.TargetImage != "" || o.TargetURL != "" || o.TargetRepo != "" || o.TargetApp != "" || o.Demo
}

// imageArg makes a local tarball path absolute and leaves registry refs alone.
func imageArg(ref string) string {
	if ref == "" {
		return ""
	}
	if st, err := os.Stat(ref); err == nil && !st.IsDir() {
		return abs(ref)
	}
	return ref
}
