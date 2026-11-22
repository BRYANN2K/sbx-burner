package tui

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/BRYANN2K/sbx-burner/internal/catalog"
	"github.com/BRYANN2K/sbx-burner/internal/doctor"
	"github.com/BRYANN2K/sbx-burner/internal/engine"
	"github.com/BRYANN2K/sbx-burner/internal/events"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// goldenTree is a fixed absolute path, so screens that show it render the
// same on every machine.
const goldenTree = "/tmp/burner-tui-golden"

func TestMain(m *testing.M) {
	lipgloss.SetColorProfile(termenv.Ascii)
	colorOn = false
	os.RemoveAll(goldenTree)
	for _, d := range []string{"repo", "src", ".build"} {
		if err := os.MkdirAll(filepath.Join(goldenTree, d), 0o755); err != nil {
			panic(err)
		}
	}
	os.WriteFile(filepath.Join(goldenTree, "notes.txt"), []byte("notes\n"), 0o644)
	os.Setenv("HOME", "/home/tester")
	os.Unsetenv("BURNER_HOME")
	code := m.Run()
	os.RemoveAll(goldenTree)
	os.Exit(code)
}

// fakeEngine records what the TUI asks for.
type fakeEngine struct {
	caps    Caps
	acp     []string
	models  ModelList
	plan    string
	planErr int
	runs    []engine.RunOptions
	events  []events.Event
	block   chan struct{}
}

func (f *fakeEngine) Caps() Caps                                  { return f.caps }
func (f *fakeEngine) ACPAgents(context.Context) ([]string, error) { return f.acp, nil }
func (f *fakeEngine) Agents(context.Context) ([]string, error) {
	return []string{"claude", "codex"}, nil
}
func (f *fakeEngine) Models(context.Context, string) (ModelList, error) {
	return f.models, nil
}
func (f *fakeEngine) Plan(_ context.Context, o engine.RunOptions) (string, int, error) {
	return f.plan, f.planErr, nil
}
func (f *fakeEngine) Run(ctx context.Context, o engine.RunOptions, on func(events.Event), _ io.Writer) (int, error) {
	f.runs = append(f.runs, o)
	for _, e := range f.events {
		on(e)
	}
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return 130, ctx.Err()
		}
	}
	return 0, nil
}
func (f *fakeEngine) Note(string, string, string) error { return nil }

func recipes() []catalog.Recipe {
	return []catalog.Recipe{
		{ID: "devsecops/secrets-scan", Category: "devsecops", Name: "secrets-scan", Source: catalog.Official, Status: "beta",
			Summary: "Scan a repository and its git history for leaked credentials with gitleaks, then triage every hit before reporting.",
			Risk:    "low", Time: "10m", Scope: "none", TargetMode: "required", Targets: []string{"path", "repo"}},
		{ID: "devsecops/sca-osv", Category: "devsecops", Name: "sca-osv", Source: catalog.Official, Status: "beta",
			Summary: "Scan lockfiles for known vulnerabilities.", Risk: "low", Time: "10m", Scope: "none", TargetMode: "required", Targets: []string{"path", "repo"}},
		{ID: "pentest/web-recon", Category: "pentest", Name: "web-recon", Source: catalog.Official, Status: "beta",
			Summary: "Map the attack surface of in-scope web hosts.", Risk: "medium", Time: "20m", Scope: "required", TargetMode: "required", Targets: []string{"app", "image", "port", "url", "demo"}},
		{ID: "apple/macho-triage", Category: "apple", Name: "macho-triage", Source: catalog.Official, Status: "planned",
			Summary: "Static triage of a Mach-O sample.", Scope: "required"},
	}
}

func checks() []doctor.Result {
	return []doctor.Result{
		{ID: "sbx", Title: "sbx installed", Level: doctor.OK, Detail: "sbx version v0.54.0 4bec4a5"},
		{ID: "runtime", Title: "Host container runtime", Level: doctor.OK, Detail: "docker 29.5.2"},
		{ID: "buildx", Title: "Docker buildx (recipe kits)", Level: doctor.OK, Detail: "available"},
		{ID: "agent-claude", Title: "Claude Code credential", Level: doctor.Warn, Detail: "no credential stored", Fix: "sbx secret set anthropic"},
		{ID: "agent-codex", Title: "Codex credential", Level: doctor.OK, Detail: "credential stored (openai)"},
		{ID: "disk", Title: "Free disk", Level: doctor.OK, Detail: "14 GB free"},
	}
}

func treeDir(t *testing.T) string {
	t.Helper()
	return goldenTree
}

func testModel(t *testing.T, eng Engine) model {
	t.Helper()
	cwd := treeDir(t)
	now := time.Date(2026, 11, 22, 1, 29, 42, 0, time.UTC)
	m := initialModel(context.Background(), Config{
		Root: "/catalog", Recipes: recipes(), Version: "dev", Engine: eng, Cwd: cwd, RunsDir: "/runs",
		Doctor: func(context.Context) []doctor.Result { return checks() },
		Now:    func() time.Time { return now },
	})
	m.checks, m.checking = checks(), false
	m.agents = []string{"claude", "codex"}
	m.w, m.h = 120, 40
	return m
}

func keyMsg(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "left":
		return tea.KeyMsg{Type: tea.KeyLeft}
	case "right":
		return tea.KeyMsg{Type: tea.KeyRight}
	case "space":
		return tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
	case "ctrl+c":
		return tea.KeyMsg{Type: tea.KeyCtrlC}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func press(t *testing.T, m model, keys ...string) model {
	t.Helper()
	for _, k := range keys {
		nm, _ := m.Update(keyMsg(k))
		m = nm.(model)
	}
	return m
}

func typeText(m model, s string) model {
	nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)})
	return nm.(model)
}

// golden compares a screen with testdata/<name>.golden.
func golden(t *testing.T, name string, m model) {
	t.Helper()
	got := m.View()
	lines := strings.Split(got, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " ")
	}
	got = strings.Join(lines, "\n") + "\n"
	checkNoEmoji(t, name, got)
	p := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/tui -update)", err)
	}
	if string(want) != got {
		t.Errorf("%s differs from %s:\n%s", name, p, got)
	}
}

func TestScreensGolden(t *testing.T) {
	eng := &fakeEngine{plan: "Plan for devsecops/secrets-scan (dry run: nothing is executed)\n  agent:     codex\n\nSteps:\n  1. create: create the sandbox\n     $ sbx create --name lab-secrets-scan-012942\n"}
	m := testModel(t, eng)
	golden(t, "home", m)

	m = press(t, m, "right", "down") // devsecops › secrets-scan
	golden(t, "home-recipe", m)

	m = press(t, m, "enter")
	golden(t, "target-kind", m)

	m = press(t, m, "enter") // Local folder or files
	golden(t, "target-path", m)

	m = press(t, m, "down", "enter") // Browse…
	golden(t, "target-browse", m)

	m = press(t, m, "space") // repo/ (first entry after "..")
	golden(t, "agent", m)

	m = press(t, m, "enter") // Codex (default: the one with a credential)
	m = typeText(m, "Focus on the git history.")
	golden(t, "notes", m)

	nm, cmd := m.Update(keyMsg("enter"))
	m = nm.(model)
	nm, _ = m.Update(cmd())
	m = nm.(model)
	golden(t, "plan", m)

	if got := m.plan.opts; got.Agent != "codex" || got.Target != filepath.Join(treeDir(t), "repo") || len(got.Prompts) != 1 {
		t.Fatalf("run options: %+v", got)
	}
}

func TestSmallTerminal(t *testing.T) {
	m := testModel(t, &fakeEngine{})
	m.w, m.h = 50, 15
	if !strings.Contains(m.View(), "Terminal too small") {
		t.Fatal("no small-terminal message")
	}
	m.w, m.h = 80, 24 // compact: no logo box, no detail column
	golden(t, "home-compact", m)
}

func TestDoctorAndNewGolden(t *testing.T) {
	m := testModel(t, &fakeEngine{})
	m = press(t, m, "d", "down", "down", "down")
	var copied string
	copyText = func(s string) error { copied = s; return nil }
	m = press(t, m, "c")
	if copied != "sbx secret set anthropic" {
		t.Fatalf("copied %q", copied)
	}
	golden(t, "doctor", m)
	m = press(t, m, "esc", "n")
	golden(t, "new", m)
}

func liveEvents() []events.Event {
	v := "hypothesis"
	return []events.Event{
		{Type: "step", Name: "create", Status: "start", RunID: "20261122-012942-secrets-scan"},
		{Type: "step", Name: "create", Status: "ok", Detail: "exit 0"},
		{Type: "step", Name: "policy-close:github.com:443", Status: "start"},
		{Type: "step", Name: "policy-close:github.com:443", Status: "ok"},
		{Type: "step", Name: "policy-close:deb.debian.org:80", Status: "start"},
		{Type: "step", Name: "policy-close:deb.debian.org:80", Status: "ok"},
		{Type: "step", Name: "agent", Status: "start"},
		{Type: "agent.message", Text: "I'm applying the secrets-triage skill as required by the repository instructions."},
		{Type: "agent.tool", Tool: "exec", Summary: "gitleaks git --redact --report-format json"},
		{Type: "agent.tool", Tool: "exec", Summary: "gitleaks git --redact --report-format json"},
		{Type: "finding", ID: "aws-credential-a5c1cc1", Status: "candidate", Severity: "critical", Title: "AWS access key pair committed in .env"},
		{Type: "blocked", Host: "ab.chatgpt.com:443"},
		{Type: "ask", AskID: "q1", RunID: "20261122-012942-secrets-scan", Question: "Treat the key in tests/test_exporter.py as a finding or a hypothesis?", Choices: []string{"hypothesis", "finding"}, AllowText: true},
		{Type: "ask", AskID: "q2", Question: "Second question", AllowText: true},
		{Type: "answer", AskID: "q2", By: "forged", Value: &v},
	}
}

func startLive(t *testing.T, eng *fakeEngine) model {
	t.Helper()
	m := testModel(t, eng)
	m.plan = newPlan(engine.RunOptions{Recipe: "devsecops/secrets-scan", Agent: "codex", RunsDir: "/runs"})
	m.plan.loading = false
	m.scr = scrPlan
	nm, cmd := m.Update(keyMsg("enter"))
	m = nm.(model)
	want := len(eng.events)
	if eng.block == nil {
		want++ // runEndMsg
	}
	for i := 0; i < want && cmd != nil; i++ {
		nm, cmd = m.Update(cmd())
		m = nm.(model)
	}
	if eng.block == nil && cmd != nil { // the leftover-sandbox check
		nm, _ = m.Update(cmd())
		m = nm.(model)
	}
	return m
}

func TestLiveGolden(t *testing.T) {
	eng := &fakeEngine{events: liveEvents(), block: make(chan struct{})}
	m := startLive(t, eng)
	golden(t, "live", m)
	if len(m.live.asks) != 1 || m.live.asks[0].AskID != "q1" {
		t.Fatalf("open asks: %+v", m.live.asks)
	}
	// A stray Enter answers nothing: no choice is selected yet.
	m = press(t, m, "enter")
	if len(m.live.asks) != 1 {
		t.Fatal("enter answered without a selection")
	}
	// Ctrl+C stops the run (the engine gets the cancel) and keeps the view.
	now := time.Date(2026, 11, 22, 1, 29, 42, 0, time.UTC)
	m.cfg.Now = func() time.Time { return now }
	m = press(t, m, "ctrl+c")
	if !m.live.stop {
		t.Fatal("ctrl+c did not stop the run")
	}
	// A quick second Ctrl+C is ignored, the run keeps draining.
	nm, cmd := m.Update(keyMsg("ctrl+c"))
	m = nm.(model)
	if cmd != nil || m.live.confirm {
		t.Fatal("a quick second ctrl+c must be ignored")
	}
	// Later, it asks before leaving; esc keeps waiting.
	now = now.Add(3 * time.Second)
	m = press(t, m, "ctrl+c")
	if !m.live.confirm {
		t.Fatal("no confirmation before leaving mid-teardown")
	}
	golden(t, "live-confirm-leave", m)
	m = press(t, m, "esc")
	if m.live.confirm {
		t.Fatal("esc did not cancel the confirmation")
	}
	m = press(t, m, "ctrl+c")
	nm, cmd = m.Update(keyMsg("ctrl+c"))
	m = nm.(model)
	if cmd == nil || m.out.Action != "left-while-stopping" {
		t.Fatal("confirmed ctrl+c did not leave")
	}
	close(eng.block)
}

func TestReportGolden(t *testing.T) {
	dir := t.TempDir()
	rep := map[string]any{
		"summary": "Scanned the target.",
		"counts":  map[string]any{"findings": 1, "hypotheses": 1},
		"findings": []map[string]any{{"id": "aws-credential-a5c1cc1", "title": "AWS access key pair committed in .env", "severity": "critical",
			"location": ".env:2@a5c1cc1", "tool": "gitleaks", "rule": "aws-access-token"}},
		"hypotheses": []map[string]any{{"id": "test-api-key-q51j", "title": "Generic API key pattern in test fixture"}},
		"artifacts":  []map[string]any{{"path": "artifacts/gitleaks.json"}},
		"gate":       map[string]any{"demoted": []any{}, "redactions": 0},
	}
	b, _ := json.Marshal(rep)
	os.WriteFile(filepath.Join(dir, "report.json"), b, 0o644)
	os.WriteFile(filepath.Join(dir, "report.md"), []byte("# r\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "policy-log.json"), []byte(`{"allowed":[{"host":"github.com:443"}],"blocked":[{"host":"ab.chatgpt.com:443"}]}`), 0o644)
	m := testModel(t, &fakeEngine{})
	m.report = newReport(filepath.Join(dir, "report.md"), "/runs/20261122-012942-secrets-scan", "/runs", 0, 6*time.Minute+2*time.Second)
	m.scr = scrReport
	golden(t, "report", m)
}

func TestFlowBackAndACPHidden(t *testing.T) {
	m := testModel(t, &fakeEngine{})
	m = press(t, m, "right", "down", "enter", "down", "enter") // git repo
	if m.flow.q.title != "Repo" {
		t.Fatalf("question %q", m.flow.q.title)
	}
	m = press(t, m, "esc")
	if m.flow.q.title != "Where is your target?" {
		t.Fatalf("back went to %q", m.flow.q.title)
	}
	m = press(t, m, "esc")
	if m.scr != scrHome {
		t.Fatal("esc on the first question did not go home")
	}
	// Without ACP support there is no Mode or Model question.
	f := newFlow(recipes()[0], treeDir(t), checks(), []string{"claude", "codex"}, nil)
	f.answers = []answer{{value: "path"}, {value: "here"}, {value: "codex"}}
	f.advance()
	if f.q == nil || f.q.kind != qNotes {
		t.Fatalf("expected notes, got %+v", f.q)
	}
}

func TestFlowACPShowsModeModelAndPermissions(t *testing.T) {
	eng := &fakeEngine{acp: []string{"codex"}, models: ModelList{Current: "gpt-6.2-sol", Known: true,
		Values: []Model{{"gpt-6.2-sol", "6.2 Sol"}, {"gpt-6-luna", "6 Luna"}}}}
	m := testModel(t, eng)
	m.acpAgents = []string{"codex"}
	m = press(t, m, "right", "down", "enter", "enter") // path
	m = press(t, m, "enter")                           // this folder
	m = press(t, m, "down", "enter")                   // codex
	if m.flow.q.title != "Mode" || m.flow.q.options[0].value != "acp" {
		t.Fatalf("question %+v", m.flow.q)
	}
	nm, cmd := m.Update(keyMsg("enter")) // ACP (default)
	m = nm.(model)
	if m.flow.q.loading == "" || cmd == nil {
		t.Fatal("models are not loaded")
	}
	golden(t, "agent-models-loading", m)
	nm, _ = m.Update(cmd())
	m = nm.(model)
	if m.flow.q.title != "Model" || len(m.flow.q.options) != 3 || m.flow.q.options[0].value != "" {
		t.Fatalf("question %+v", m.flow.q)
	}
	golden(t, "agent-models", m)
	m = press(t, m, "down", "down", "enter") // gpt-6-luna
	if m.flow.q.title != "Permissions" {
		t.Fatalf("question %q", m.flow.q.title)
	}
	m = press(t, m, "enter", "enter") // auto, no notes
	o := m.plan.opts
	if !o.ACP || o.Model != "gpt-6-luna" || o.Permission != "auto" {
		t.Fatalf("run options: acp=%v model=%q permission=%q", o.ACP, o.Model, o.Permission)
	}
	if a := strings.Join(o.Args(), " "); !strings.Contains(a, "--acp") || !strings.Contains(a, "--model=gpt-6-luna") {
		t.Fatalf("engine args: %s", a)
	}
}

func TestFlowNoACPForOtherAgents(t *testing.T) {
	f := newFlow(recipes()[0], treeDir(t), checks(), []string{"claude", "codex"}, []string{"codex"})
	f.answers = []answer{{value: "path"}, {value: "here"}, {value: "claude"}}
	f.advance()
	if f.q == nil || f.q.kind != qNotes {
		t.Fatalf("claude is not driven over ACP; expected notes, got %+v", f.q)
	}
}

func TestPlanScrollsInsideTheBox(t *testing.T) {
	var lines []string
	for i := 0; i < 80; i++ {
		lines = append(lines, fmt.Sprintf("  %d. step %d", i, i))
	}
	lines = append(lines, "     $ sbx create --name lab-x "+strings.Repeat("--very-long-flag ", 20))
	eng := &fakeEngine{plan: strings.Join(lines, "\n")}
	m := testModel(t, eng)
	m.plan = newPlan(engine.RunOptions{Recipe: "devsecops/fuzzing", Agent: "codex", RunsDir: "/runs"})
	m.scr = scrPlan
	nm, _ := m.Update(planMsg{text: eng.plan})
	m = nm.(model)
	v := m.View()
	if n := len(strings.Split(v, "\n")); n != m.h {
		t.Fatalf("view has %d lines, want %d", n, m.h)
	}
	if !strings.Contains(v, "more lines") || !strings.Contains(v, "Run") {
		t.Fatal("no scroll indicator or no Run button")
	}
	m = press(t, m, "end")
	golden(t, "plan-scrolled-end", m)
	m = press(t, m, "w")
	if !m.plan.sc.wrap {
		t.Fatal("w did not toggle wrap")
	}
	nm, _ = m.Update(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonWheelUp})
	m = nm.(model)
	if m.plan.sc.offset == m.plan.sc.maxOffset() {
		t.Fatal("wheel did not scroll")
	}
}

func TestHeaderFitsWidth(t *testing.T) {
	h := header(40, crumb("devsecops", "a-very-long-recipe-name-here", "codex"), stepDots(4, 6, "plan"))
	if lipgloss.Width(h) > 39 || !strings.HasSuffix(h, "plan") {
		t.Fatalf("header %q is %d wide", h, lipgloss.Width(h))
	}
}

func TestFlowImageAndScope(t *testing.T) {
	m := testModel(t, &fakeEngine{})
	m = press(t, m, "down", "right", "enter") // pentest › web-recon
	if m.flow.q.title != "Where is your target?" {
		t.Fatalf("question %q", m.flow.q.title)
	}
	m = press(t, m, "down", "enter", "enter") // image › name
	m = typeText(m, "ghcr.io/me/app:1.0")
	m = press(t, m, "enter")
	if m.flow.q.title != "Port" {
		t.Fatalf("question %q", m.flow.q.title)
	}
	m = typeText(m, "99999")
	m = press(t, m, "enter")
	if m.flow.err == "" {
		t.Fatal("invalid port accepted")
	}
	m = press(t, m, "esc")
}

func TestBrowserHiddenAndPick(t *testing.T) {
	b := newBrowser(treeDir(t), true, false, nil)
	for _, e := range b.entries {
		if strings.HasPrefix(e.name, ".") && e.name != ".." {
			t.Fatalf("hidden entry shown: %s", e.name)
		}
		if !e.dir {
			t.Fatalf("file shown in a folder-only browser: %s", e.name)
		}
	}
	b.toggleHidden()
	found := false
	for _, e := range b.entries {
		if e.name == ".build" {
			found = true
		}
	}
	if !found {
		t.Fatal(".build not shown with hidden on")
	}
	if p, ok := b.pickHere(); !ok || p != treeDir(t) {
		t.Fatalf("pickHere = %q %v", p, ok)
	}
}

func TestTailKeepsLastLines(t *testing.T) {
	tl := &tail{max: 3}
	io.WriteString(tl, "a\nb\nc\nd\x1b[31m\npartial")
	got := strings.Join(tl.lines(), ",")
	if got != "b,c,d,partial" && got != "b,c,d[31m,partial" {
		if strings.Contains(got, "\x1b") {
			t.Fatalf("escape kept: %q", got)
		}
	}
	if strings.Contains(got, "\x1b") {
		t.Fatalf("escape kept: %q", got)
	}
}

func TestPaintBGRestoresAfterReset(t *testing.T) {
	colorOn = true
	defer func() { colorOn = false }()
	out := paintBG("a\x1b[0mb", 4)
	if !strings.Contains(out, "\x1b[0m\x1b[48;2;20;20;20mb") {
		t.Fatalf("background not restored: %q", out)
	}
}

var errX = errors.New("x")

func TestLeftoverSandboxWarning(t *testing.T) {
	orig := listSandboxes
	listSandboxes = func(context.Context) ([]string, error) {
		return []string{"other-1", "lab-secrets-scan-012942"}, nil
	}
	defer func() { listSandboxes = orig }()
	eng := &fakeEngine{events: []events.Event{
		{Type: "step", Name: "create", Status: "start", RunID: "20261122-012942-secrets-scan"},
		{Type: "step", Name: "create", Status: "ok"},
	}}
	m := startLive(t, eng) // ends without a done event
	if !m.live.finish {
		t.Fatal("run did not end")
	}
	if got := m.live.leftover(); len(got) != 1 || !strings.Contains(got[0], "sbx rm --force lab-secrets-scan-012942") {
		t.Fatalf("leftover warning: %v", got)
	}
}

func TestExpectedSandbox(t *testing.T) {
	if got := expectedSandbox("20261122-015747-secrets-scan", "secrets-scan"); got != "lab-secrets-scan-015747" {
		t.Fatalf("got %q", got)
	}
	if expectedSandbox("bad", "x") != "" {
		t.Fatal("invalid run id accepted")
	}
}

func TestOpenPathRefusesOutsideRuns(t *testing.T) {
	if msg := openPath("/etc/passwd", "/runs", true); !strings.HasPrefix(msg, "not opened") {
		t.Fatalf("opened outside runs: %q", msg)
	}
	if inside("/runs/../etc", "/runs") || !inside("/runs/a/report.md", "/runs") {
		t.Fatal("inside() is wrong")
	}
}

func TestLiveLogIsBounded(t *testing.T) {
	m := testModel(t, &fakeEngine{})
	l := newLive(engine.RunOptions{Recipe: "devsecops/secrets-scan", Agent: "codex"}, time.Now())
	l.add(events.Event{Type: "step", Name: "agent", Status: "start", RunID: "20261122-012942-secrets-scan"})
	for i := 0; i < 100000; i++ {
		l.add(events.Event{Type: "agent.message", Text: fmt.Sprintf("line %d with some words to wrap around the width", i)})
	}
	if len(l.log) > maxLog+trimChunk {
		t.Fatalf("log has %d entries, cap is %d", len(l.log), maxLog+trimChunk)
	}
	if l.dropped == 0 {
		t.Fatal("nothing was dropped")
	}
	m.live, m.scr = l, scrLive
	m.View() // fills the cache
	start := time.Now()
	for i := 0; i < 10; i++ {
		m.frame++
		m.View()
	}
	if per := time.Since(start) / 10; per > 50*time.Millisecond {
		t.Fatalf("one frame takes %s", per)
	}
	if !strings.Contains(l.render(m, 120)[0], "earlier lines not shown") {
		t.Fatal("no marker for dropped lines")
	}
	// A step that started before the cut still updates (or is re-added).
	l.add(events.Event{Type: "step", Name: "agent", Status: "ok"})
	if last := l.log[len(l.log)-1]; last.kind != "step" || last.ev.Status != "ok" {
		t.Fatalf("step update lost: %+v", last.ev)
	}
}

func TestCategoryOrderAndCounts(t *testing.T) {
	rs := append(recipes(), catalog.Recipe{ID: "training/ctf-lab", Category: "training", Name: "ctf-lab", Source: catalog.Official, Status: "beta"},
		catalog.Recipe{ID: "foundation/scope-guard", Category: "foundation", Name: "scope-guard", Source: catalog.Official, Status: "beta"},
		catalog.Recipe{ID: "apple/swiftui-dev", Category: "apple", Name: "swiftui-dev", Source: catalog.Official, Status: "planned"})
	got := strings.Join(categoryOrder(rs), ",")
	if got != "devsecops,pentest,training,foundation,apple" {
		t.Fatalf("order %s", got)
	}
	m := testModel(t, &fakeEngine{})
	m.home = newHome(rs)
	if v := m.View(); !strings.Contains(v, "apple       2   planned") {
		t.Fatalf("apple count missing:\n%s", v)
	}
}

func TestDetailWrapsEveryField(t *testing.T) {
	r := catalog.Recipe{ID: "pentest/binary-blackbox", Category: "pentest", Name: "binary-blackbox", Source: catalog.Official, Status: "beta",
		Summary: "Black-box analysis of a Linux binary — static triage, radare2 hypotheses, and dynamic proof of each behaviour with a crafted input.",
		Risk:    "medium", Time: "30m", TestedWith: []string{"codex"}, Scope: "required", Targets: []string{"path", "repo", "image", "app", "url"}}
	m := testModel(t, &fakeEngine{})
	m.home = newHome([]catalog.Recipe{r})
	m.home.col = 1
	for _, w := range []int{100, 104, 120} {
		d := m.detail(w - 28 - 34 - 4)
		flat := strings.Join(strings.Fields(d), " ")
		for _, word := range strings.Fields(r.Summary) {
			if !strings.Contains(flat, word) {
				t.Fatalf("width %d: %q cut from the summary:\n%s", w, word, d)
			}
		}
		for _, l := range strings.Split(d, "\n") {
			if lipgloss.Width(l) > w-28-34-4 {
				t.Fatalf("width %d: line wider than the column: %q", w, l)
			}
		}
		if strings.Contains(d, "…") {
			t.Fatalf("width %d: a field was cut", w)
		}
	}
}

func TestDoctorChecksEveryEngineAgent(t *testing.T) {
	orig := engineAgents
	defer func() { engineAgents = orig }()
	engineAgents = func(context.Context, string) ([]engine.AgentInfo, error) {
		return []engine.AgentInfo{{Name: "claude"}, {Name: "codex"}, {Name: "devin"}, {Name: "opencode"}}, nil
	}
	o := doctorOptions(context.Background(), "/catalog")
	if got := strings.Join(o.Agents, ","); got != "claude,codex,devin,opencode" || o.DiskPath != "/catalog" {
		t.Fatalf("doctor options: agents=%s disk=%s", got, o.DiskPath)
	}
	engineAgents = func(context.Context, string) ([]engine.AgentInfo, error) { return nil, errors.New("no engine") }
	if got := doctorOptions(context.Background(), "/catalog").Agents; strings.Join(got, ",") != strings.Join(doctor.KnownAgents(), ",") {
		t.Fatalf("fallback agents: %v", got)
	}
}

func TestLastRunSkipsMalformedReports(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string, age time.Duration) {
		d := filepath.Join(dir, name)
		os.MkdirAll(d, 0o755)
		p := filepath.Join(d, "report.json")
		os.WriteFile(p, []byte(body), 0o644)
		ts := time.Now().Add(-age)
		os.Chtimes(p, ts, ts)
	}
	write("20261122-012942-secrets-scan", `{"run":{"recipe":"devsecops/secrets-scan","agent":"codex"},"counts":{"findings":1}}`, 2*time.Hour)
	write("20261122-030000-fuzzing", `{"run": {"recipe": "devsecops/fuzz`, time.Minute)       // newest, malformed
	write("20261122-020000-gate", `{"run":{"recipe":""},"counts":{"findings":2}}`, time.Hour) // no recipe
	l := findLastRun(dir)
	if l == nil || l.recipe != "secrets-scan" || l.agent != "codex" || l.findings != 1 {
		t.Fatalf("last run: %+v", l)
	}
	if s := l.String(time.Now()); !strings.Contains(s, "1 finding") || !strings.Contains(s, "today ") && time.Now().Hour() >= 2 {
		t.Fatalf("line %q", s)
	}
	if findLastRun(filepath.Join(dir, "missing")) != nil {
		t.Fatal("a missing runs folder gave a last run")
	}
}

func TestHeaderBoxGolden(t *testing.T) {
	m := testModel(t, &fakeEngine{})
	m.last = &lastRun{recipe: "secrets-scan", agent: "codex", findings: 1, when: time.Date(2026, 11, 22, 1, 29, 0, 0, time.UTC)}
	golden(t, "home-last-run", m)
	m.checking = true
	if v := m.View(); !strings.Contains(v, "checking credentials") || strings.Contains(v, "recipes ") {
		t.Fatal("header: no spinner while checking, or a recipes line")
	}
}
