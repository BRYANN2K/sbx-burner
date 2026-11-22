// Package live runs a recipe with the runner's event stream and shows it:
// steps, what the agent says and does, findings, blocked hosts. When the
// agent asks a question, the user answers here (choices or text) and the
// answer goes to the run's control socket.
package live

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/x/term"

	"github.com/BRYANN2K/sbx-burner/internal/engine"
	"github.com/BRYANN2K/sbx-burner/internal/events"
)

// Asker answers a question; tests replace the interactive one.
type Asker func(e events.Event) (string, bool)

// Options for Run.
type Options struct {
	Out  io.Writer // human view
	JSON bool      // pass events through as NDJSON instead of the view
	Ask  Asker     // nil: never answer here (unattended)
	// Handoff runs the agent's own TUI on the terminal (--interactive);
	// nil: the run cannot be interactive here.
	Handoff func(argv []string) error
	RunsDir string
}

// State tracks what the view needs to warn about.
type State struct {
	mu       sync.Mutex
	pending  map[string]events.Event
	handoff  []string        // argv of the pending agent handoff
	answered map[string]bool // answers burner itself sent
	Forged   []string
	Findings map[string]events.Event
	Done     *events.Event
	RunID    string
}

// Run executes the engine with --events - and renders the stream.
func Run(ctx context.Context, root string, o engine.RunOptions, opts Options) (int, *State, error) {
	if opts.Out == nil {
		opts.Out = os.Stderr
	}
	o.Events = "-"
	if o.RunsDir == "" {
		o.RunsDir = opts.RunsDir
	}
	if o.RunsDir == "" {
		cwd, _ := os.Getwd()
		o.RunsDir = cwd + "/runs"
	}
	pr, pw := io.Pipe()
	st := &State{pending: map[string]events.Event{}, answered: map[string]bool{}, Findings: map[string]events.Event{}}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = events.Read(pr, func(e events.Event) { handle(e, o.RunsDir, st, opts) })
	}()
	code, err := engine.ExecStreams(ctx, root, o.Args(), nil, pw, os.Stderr)
	pw.Close()
	wg.Wait()
	summary(st, opts)
	return code, st, err
}

func handle(e events.Event, runsDir string, st *State, opts Options) {
	st.mu.Lock()
	if st.RunID == "" {
		st.RunID = e.RunID
	}
	st.mu.Unlock()
	if opts.JSON {
		raw := fmt.Sprintf("%s\n", mustJSON(e))
		io.WriteString(opts.Out, raw)
	} else {
		Render(opts.Out, e)
	}
	switch e.Type {
	case "finding":
		st.mu.Lock()
		st.Findings[e.ID] = e
		st.mu.Unlock()
	case "done":
		st.mu.Lock()
		ev := e
		st.Done = &ev
		st.mu.Unlock()
	case "answer":
		st.mu.Lock()
		delete(st.pending, e.AskID)
		if e.By == "forged" {
			st.Forged = append(st.Forged, e.AskID)
		}
		st.mu.Unlock()
		if e.By == "forged" && !opts.JSON {
			fmt.Fprintf(opts.Out, "  ! WARNING: the agent wrote its own answer to %s. Only answers given here count.\n", e.AskID)
		}
	case "handoff":
		st.mu.Lock()
		run := st.RunID
		st.mu.Unlock()
		argv, err := events.HandoffArgv(e, run, events.SandboxForRun(run), filepath.Join(runsDir, run, "workspace"))
		if err != nil {
			fmt.Fprintf(opts.Out, "  ! refused handoff: %v\n", err)
			return
		}
		st.mu.Lock()
		st.handoff = argv
		st.mu.Unlock()
	case "ask":
		st.mu.Lock()
		st.pending[e.AskID] = e
		argv := st.handoff
		st.mu.Unlock()
		if e.AskID == events.InteractiveAsk {
			// The runner waits on this ask while the operator uses the
			// agent's TUI; answer "done" when it exits.
			if argv == nil || opts.Handoff == nil {
				return
			}
			if !opts.JSON {
				fmt.Fprintf(opts.Out, "  › opening the agent's own TUI (quit it to continue the run)\n")
			}
			if err := opts.Handoff(argv); err != nil && !opts.JSON {
				fmt.Fprintf(opts.Out, "  ! agent TUI: %v\n", err)
			}
			if err := events.Answer(events.SocketPath(runsDir, e.RunID), e.AskID, "done"); err != nil {
				fmt.Fprintf(opts.Out, "  ! could not tell the runner: %v\n", err)
			}
			return
		}
		if opts.Ask == nil {
			return
		}
		// Ask in the background: events keep flowing while the user thinks.
		go func(e events.Event) {
			value, ok := opts.Ask(e)
			if !ok {
				return
			}
			st.mu.Lock()
			still := st.pending[e.AskID].AskID != ""
			st.mu.Unlock()
			if !still {
				return // timed out or answered elsewhere
			}
			if err := events.Answer(events.SocketPath(runsDir, e.RunID), e.AskID, value); err != nil {
				fmt.Fprintf(opts.Out, "  ! could not deliver the answer: %v\n", err)
				return
			}
			st.mu.Lock()
			st.answered[e.AskID] = true
			st.mu.Unlock()
		}(e)
	}
}

// Render prints one event as a readable line.
func Render(w io.Writer, e events.Event) {
	switch e.Type {
	case "step":
		mark := map[string]string{"start": "…", "ok": "✓", "fail": "✗", "skip": "–"}[e.Status]
		if e.Status == "start" {
			return // the ok/fail line is enough
		}
		line := fmt.Sprintf("%s %s", mark, e.Name)
		if e.Detail != "" {
			line += " · " + e.Detail
		}
		fmt.Fprintln(w, line)
	case "agent.message":
		for _, l := range strings.Split(strings.TrimSpace(e.Text), "\n") {
			fmt.Fprintln(w, "  "+l)
		}
	case "agent.tool":
		// An ACP tool call (with an id) prints once, when it ends; its
		// output stays in the TUI.
		switch {
		case e.ID == "":
			fmt.Fprintln(w, ToolLine(e.Tool, e.Summary, Width()))
		case e.Tool == "output":
		case e.Status == "completed":
			fmt.Fprintln(w, ToolLine(e.Tool, e.Summary, Width()))
		case e.Status == "failed":
			fmt.Fprintln(w, ToolLine("failed", e.Summary, Width()))
		}
	case "finding":
		extra := e.Severity
		if e.CVSS != "" {
			extra += " · " + e.CVSS
		}
		fmt.Fprintf(w, "◆ %s %s [%s] %s\n", e.ID, e.Status, extra, e.Title)
	case "blocked":
		fmt.Fprintf(w, "  ⊘ blocked %s (not in scope)\n", e.Host)
	case "ask":
		fmt.Fprintf(w, "? %s: %s\n", e.AskID, e.Question)
	case "answer":
		v := "no answer"
		if e.Value != nil {
			v = *e.Value
		}
		fmt.Fprintf(w, "  → %s: %s (%s)\n", e.AskID, v, e.By)
	case "done":
		fmt.Fprintf(w, "■ done · exit %d · %s\n", e.ExitCode, e.Report)
	}
}

// Width is the terminal width used to cut tool lines; tests replace it.
var Width = func() int {
	for _, f := range []*os.File{os.Stderr, os.Stdout} {
		if w, _, err := term.GetSize(f.Fd()); err == nil && w > 20 {
			return w
		}
	}
	return 100
}

// ToolLine renders a tool call as one line: `  › <title>`. Ordinary tool
// kinds (execute, read, edit...) are not shown; burner's own notes
// (permission, failed) keep their label. The full text stays in the
// transcript and the event stream.
func ToolLine(tool, summary string, width int) string {
	text := strings.Join(strings.Fields(summary), " ")
	if tool == "permission" || tool == "failed" {
		text = tool + ": " + text
	}
	line := "  › " + text
	r := []rune(line)
	if width > 8 && len(r) > width {
		line = string(r[:width-1]) + "…"
	}
	return line
}

func summary(st *State, opts Options) {
	if opts.JSON {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	proven := 0
	for _, f := range st.Findings {
		if f.Status == "proven" {
			proven++
		}
	}
	fmt.Fprintf(opts.Out, "\nFindings: %d proven · %d total\n", proven, len(st.Findings))
	if len(st.Forged) > 0 {
		fmt.Fprintf(opts.Out, "WARNING: %d answer(s) were written by the agent, not by you: %s\n", len(st.Forged), strings.Join(st.Forged, ", "))
	}
}

// Interactive asks in the terminal: a choice list, plus a free-text option
// when the agent allows text.
func Interactive(e events.Event) (string, bool) {
	const other = "\x00other"
	var value string
	if len(e.Choices) > 0 {
		opts := []huh.Option[string]{}
		for _, c := range e.Choices {
			opts = append(opts, huh.NewOption(c, c))
		}
		if e.AllowText {
			opts = append(opts, huh.NewOption("Type an answer…", other))
		}
		if err := huh.NewSelect[string]().Title(e.Question).Options(opts...).Value(&value).Run(); err != nil {
			return "", false
		}
		if value != other {
			return value, true
		}
		value = ""
	}
	if !e.AllowText && len(e.Choices) == 0 {
		return "", false
	}
	if err := huh.NewInput().Title(e.Question).Value(&value).Run(); err != nil {
		return "", false
	}
	return strings.TrimSpace(value), true
}

func mustJSON(e events.Event) string {
	b, _ := e.MarshalJSON()
	return string(b)
}
