// Package tui is burner's full-screen interactive mode: browse the catalog,
// answer only the questions a recipe needs, review the engine's plan, watch
// the run live, read the report.
package tui

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/BRYANN2K/sbx-burner/internal/catalog"
	"github.com/BRYANN2K/sbx-burner/internal/doctor"
	"github.com/BRYANN2K/sbx-burner/internal/engine"
)

// ErrAborted is returned when the user leaves without running anything.
var ErrAborted = errors.New("aborted")

// Config is what the TUI starts from.
type Config struct {
	Root    string
	Recipes []catalog.Recipe
	Version string
	Engine  Engine                                // nil: the real engine in Root
	Doctor  func(context.Context) []doctor.Result // nil: doctor.Check
	Cwd     string                                // "" : os.Getwd
	RunsDir string                                // "" : <cwd>/runs
	Now     func() time.Time                      // tests freeze time
}

// Outcome tells main what happened, and what to run after the TUI exits.
type Outcome struct {
	Code    int
	Action  string // "update": run `burner update` after the TUI
	Command string // the last run as a flag command, to print on exit
	Report  string
}

// engineAgents lists the runner's agents; tests replace it.
var engineAgents = engine.Agents

// doctorOptions checks the credentials of every agent the engine knows,
// or burner's own list when the engine cannot be asked.
func doctorOptions(ctx context.Context, root string) doctor.Options {
	o := doctor.Options{DiskPath: root}
	if as, err := engineAgents(ctx, root); err == nil && len(as) > 0 {
		o.Agents = engine.AgentNames(as)
	} else {
		o.Agents = doctor.KnownAgents()
	}
	return o
}

// Min terminal size.
const minW, minH = 60, 20

type screen int

const (
	scrHome screen = iota
	scrFlow
	scrPlan
	scrLive
	scrReport
	scrDoctor
	scrNew
	scrLog
)

type model struct {
	ctx context.Context
	cfg Config
	eng Engine

	w, h  int
	frame int
	seed  int64 // logo sparks and blinks
	scr   screen

	checks   []doctor.Result
	checking bool

	agents    []string // every agent the runner can launch
	acpAgents []string
	tuis      map[string][]string
	last      *lastRun

	home   homeModel
	flow   *flowModel
	plan   *planModel
	live   *liveModel
	report *reportModel
	doc    doctorModel
	newr   *newModel
	logv   *logModel

	out Outcome
}

type tickMsg struct{}
type checksMsg []doctor.Result
type acpAgentsMsg []string
type tuisMsg map[string][]string
type agentsMsg []string

func tick() tea.Cmd {
	return tea.Tick(80*time.Millisecond, func(time.Time) tea.Msg { return tickMsg{} })
}

func initialModel(ctx context.Context, cfg Config) model {
	if cfg.Engine == nil {
		cfg.Engine = realEngine{root: cfg.Root}
	}
	if cfg.Doctor == nil {
		root := cfg.Root
		cfg.Doctor = func(ctx context.Context) []doctor.Result {
			return doctor.Check(ctx, doctorOptions(ctx, root))
		}
	}
	if cfg.Cwd == "" {
		cfg.Cwd, _ = os.Getwd()
	}
	if cfg.RunsDir == "" {
		cfg.RunsDir = cfg.Cwd + "/runs"
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	m := model{ctx: ctx, cfg: cfg, eng: cfg.Engine, w: 120, h: 40, checking: true, seed: cfg.Now().UnixNano()}
	m.home = newHome(cfg.Recipes)
	m.out.Code = 130
	return m
}

func (m model) runChecks() tea.Cmd {
	ctx, fn := m.ctx, m.cfg.Doctor
	return func() tea.Msg { return checksMsg(fn(ctx)) }
}

func (m model) Init() tea.Cmd {
	ctx, eng := m.ctx, m.eng
	runs := m.cfg.RunsDir
	return tea.Batch(tick(), m.runChecks(), func() tea.Msg {
		a, _ := eng.ACPAgents(ctx)
		return acpAgentsMsg(a)
	}, func() tea.Msg {
		a, _ := eng.Agents(ctx)
		return agentsMsg(a)
	}, func() tea.Msg {
		t, _ := eng.AgentTUIs(ctx)
		return tuisMsg(t)
	}, func() tea.Msg { return lastRunMsg(findLastRun(runs)) })
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		return m, nil
	case tickMsg:
		m.frame++
		return m, tick()
	case lastRunMsg:
		m.last = msg
		return m, nil
	case tuisMsg:
		m.tuis = msg
		return m, nil
	case acpAgentsMsg:
		m.acpAgents = msg
		return m, nil
	case agentsMsg:
		m.agents = msg
		return m, nil
	case checksMsg:
		m.checks, m.checking = msg, false
		m.doc.checking = false
		return m, nil
	case tea.KeyMsg:
		// Ctrl+C everywhere but the live run quits; the live run stops and
		// destroys the sandbox first.
		if msg.String() == "ctrl+c" && m.scr != scrLive {
			return m, tea.Quit
		}
	}
	switch m.scr {
	case scrHome:
		return m.updateHome(msg)
	case scrFlow:
		return m.updateFlow(msg)
	case scrPlan:
		return m.updatePlan(msg)
	case scrLive:
		return m.updateLive(msg)
	case scrReport:
		return m.updateReport(msg)
	case scrDoctor:
		return m.updateDoctor(msg)
	case scrNew:
		return m.updateNew(msg)
	case scrLog:
		return m.updateLog(msg)
	}
	return m, nil
}

func (m model) View() string {
	if m.w < minW || m.h < minH {
		return paintBG(sDim.Render("Terminal too small: burner needs 60×20.")+"\n"+sDim.Render("q quit"), m.w)
	}
	var v string
	switch m.scr {
	case scrHome:
		v = m.viewHome()
	case scrFlow:
		v = m.viewFlow()
	case scrPlan:
		v = m.viewPlan()
	case scrLive:
		v = m.viewLive()
	case scrReport:
		v = m.viewReport()
	case scrDoctor:
		v = m.viewDoctor()
	case scrNew:
		v = m.viewNew()
	case scrLog:
		v = m.viewLog()
	}
	return paintBG(fit(v, m.w, m.h), m.w)
}

// fit pads or cuts the view to the terminal height, keeping the last line
// (the key hints) at the bottom.
func fit(v string, w, h int) string {
	lines := strings.Split(strings.TrimRight(v, "\n"), "\n")
	for i, l := range lines {
		if lipgloss.Width(l) > w {
			lines[i] = truncateANSI(l, w)
		}
	}
	if len(lines) > h {
		last := lines[len(lines)-1]
		lines = append(lines[:h-1], last)
	}
	if len(lines) < h {
		last := lines[len(lines)-1]
		body := lines[:len(lines)-1]
		for len(body) < h-1 {
			body = append(body, "")
		}
		lines = append(body, last)
	}
	return strings.Join(lines, "\n")
}

func truncateANSI(s string, w int) string {
	return lipgloss.NewStyle().MaxWidth(w).Render(s)
}

func (m model) spin() string { return spinFrames[m.frame%len(spinFrames)] }

// crumb is the top-left breadcrumb.
func crumb(parts ...string) string {
	return sDim.Render(strings.Join(parts, " › "))
}

// stepDots renders "step ▰▰▱▱▱ label" on the right of the header. ▰ and ▱
// are narrow in every terminal (● is drawn wide by some).
func stepDots(done, total int, label string) string {
	return sDim.Render("step ") + sAmber.Render(strings.Repeat("▰", done)) + sFaint.Render(strings.Repeat("▱", total-done)) + "  " + sDim.Render(label)
}

// header puts left and right on one line of width w, cutting the left part
// first; the last column stays free.
func header(w int, left, right string) string {
	w--
	rw := lipgloss.Width(right)
	if rw > w {
		right = ellipsis(right, w)
		rw = lipgloss.Width(right)
	}
	if lipgloss.Width(left)+rw+1 > w {
		left = ellipsis(left, max(1, w-rw-1))
	}
	pad := w - lipgloss.Width(left) - rw
	if pad < 1 {
		pad = 1
	}
	return left + strings.Repeat(" ", pad) + right
}

// Run starts the full-screen program.
func Run(ctx context.Context, cfg Config) (Outcome, error) {
	setupColor()
	p := tea.NewProgram(initialModel(ctx, cfg), tea.WithAltScreen(), tea.WithMouseCellMotion(), tea.WithContext(ctx))
	final, err := p.Run()
	if err != nil && !errors.Is(err, tea.ErrProgramKilled) {
		return Outcome{Code: 1}, err
	}
	fm, ok := final.(model)
	if !ok {
		return Outcome{Code: 1}, nil
	}
	if fm.out.Code == 130 && fm.out.Action == "" && fm.out.Report == "" {
		return fm.out, ErrAborted
	}
	return fm.out, nil
}

// optsCommand is the same run without the menu.
func optsCommand(o engine.RunOptions) string {
	return "burner " + shellJoin(o.Args())
}

func shellJoin(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " '\"$`\\*?;&|<>()") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		out[i] = a
	}
	return strings.Join(out, " ")
}
