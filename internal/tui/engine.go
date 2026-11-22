package tui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/BRYANN2K/sbx-burner/internal/engine"
	"github.com/BRYANN2K/sbx-burner/internal/events"
	"github.com/BRYANN2K/sbx-burner/internal/sanitize"
)

// Caps says what the engine supports beyond a headless run.
type Caps struct {
	MidRunNotes bool // notes sent to the agent during a run
}

// ModelList is what `burner models --agent A --json` returns.
type ModelList struct {
	Current string  `json:"current"`
	Values  []Model `json:"values"`
	Known   bool    `json:"known"`
}

// Model is one model the agent offers.
type Model struct {
	Value string `json:"Value"`
	Name  string `json:"Name"`
}

// Engine is what the TUI needs from the runner. Tests use a fake.
type Engine interface {
	Caps() Caps
	// ACPAgents lists the agents burner can drive over ACP.
	ACPAgents(ctx context.Context) ([]string, error)
	// Models lists the models an ACP agent offers.
	Models(ctx context.Context, agent string) (ModelList, error)
	// Plan runs the engine's dry run and returns its output.
	Plan(ctx context.Context, o engine.RunOptions) (string, int, error)
	// Run executes the recipe with the event stream. Cancelling ctx
	// interrupts the engine, which still destroys the sandbox.
	Run(ctx context.Context, o engine.RunOptions, onEvent func(events.Event), stderr io.Writer) (int, error)
	// Note sends an operator note to a running agent (MidRunNotes).
	Note(runsDir, runID, text string) error
}

// realEngine drives `python -m lab` in the catalog root, and burner itself
// for the ACP lists.
type realEngine struct{ root string }

func (e realEngine) Caps() Caps { return Caps{} }

// burnerJSON runs this burner binary with args and decodes its JSON output.
func burnerJSON(ctx context.Context, timeout time.Duration, v any, args ...string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, self, args...).Output()
	if err != nil {
		return err
	}
	if len(out) > 1<<20 {
		return errors.New("output too large")
	}
	return json.Unmarshal(out, v)
}

func (e realEngine) ACPAgents(ctx context.Context) ([]string, error) {
	var v struct {
		Agents []string `json:"acp_agents"`
	}
	err := burnerJSON(ctx, 15*time.Second, &v, "acp", "agents", "--json")
	return v.Agents, err
}

func (e realEngine) Models(ctx context.Context, agent string) (ModelList, error) {
	var v ModelList
	// May start a throwaway session when nothing is cached yet.
	err := burnerJSON(ctx, 3*time.Minute, &v, "--catalog", e.root, "models", "--agent", agent, "--json")
	for i := range v.Values {
		v.Values[i].Value = sanitize.Line(v.Values[i].Value, 120)
		v.Values[i].Name = sanitize.Line(v.Values[i].Name, 120)
	}
	v.Current = sanitize.Line(v.Current, 120)
	return v, err
}

func (e realEngine) Plan(ctx context.Context, o engine.RunOptions) (string, int, error) {
	o.DryRun = true
	var buf bytes.Buffer
	code, err := engine.ExecTo(ctx, e.root, o.Args(), &buf)
	return buf.String(), code, err
}

func (e realEngine) Run(ctx context.Context, o engine.RunOptions, onEvent func(events.Event), stderr io.Writer) (int, error) {
	o.Events = "-"
	pr, pw := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = events.Read(pr, onEvent)
	}()
	code, err := engine.ExecInterruptible(ctx, e.root, o.Args(), pw, stderr)
	pw.Close()
	<-done
	return code, err
}

func (e realEngine) Note(string, string, string) error { return nil }
