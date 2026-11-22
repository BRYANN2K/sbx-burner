package tui

import (
	"os"
	"os/exec"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/BRYANN2K/sbx-burner/internal/engine"
	"github.com/BRYANN2K/sbx-burner/internal/sanitize"
)

// planModel shows the engine's own dry run: exactly what will run.
type planModel struct {
	opts    engine.RunOptions
	loading bool
	text    string
	code    int
	err     error
	sc      scroller
	run     bool // Run button selected (else Cancel)
}

type planMsg struct {
	text string
	code int
	err  error
}

// approveDoneMsg is sent when `burner approve` returns; the plan is
// re-checked so an approved binding turns the refusal into a runnable plan.
type approveDoneMsg struct{ err error }

// approveAgent finds the agent a refused plan asks to approve: the engine
// prints `run: burner approve --agent <name>` when a mixin kit's credential
// binding is missing.
func approveAgent(text string) string {
	const marker = "burner approve --agent "
	for _, l := range strings.Split(text, "\n") {
		if i := strings.Index(l, marker); i >= 0 {
			if fields := strings.Fields(l[i+len(marker):]); len(fields) > 0 {
				return fields[0]
			}
		}
	}
	return ""
}

// approveCmd runs `burner approve --agent` on the user's terminal so sbx's
// own prompt records the credential binding.
func approveCmd(agent string) tea.Cmd {
	self, err := os.Executable()
	if err != nil {
		return func() tea.Msg { return approveDoneMsg{err: err} }
	}
	return tea.ExecProcess(exec.Command(self, "approve", "--agent", agent), func(err error) tea.Msg {
		return approveDoneMsg{err: err}
	})
}

func newPlan(o engine.RunOptions) *planModel {
	return &planModel{opts: o, loading: true, run: true}
}

func (p *planModel) start(m model) tea.Cmd {
	ctx, eng, o := m.ctx, m.eng, p.opts
	if o.RunsDir == "" {
		o.RunsDir = m.cfg.RunsDir
	}
	p.opts = o
	return func() tea.Msg {
		t, c, err := eng.Plan(ctx, o)
		return planMsg{text: t, code: c, err: err}
	}
}

func (p *planModel) ok() bool { return !p.loading && p.err == nil && p.code == 0 }

func (m model) updatePlan(msg tea.Msg) (tea.Model, tea.Cmd) {
	p := m.plan
	switch msg := msg.(type) {
	case planMsg:
		p.loading, p.text, p.code, p.err = false, sanitize.Text(msg.text, 64*1024), msg.code, msg.err
		p.run = p.ok()
		return m, nil
	case approveDoneMsg:
		p.loading = true
		return m, p.start(m)
	case tea.MouseMsg:
		p.sc.mouse(msg)
		return m, nil
	case tea.KeyMsg:
		if p.sc.key(msg.String(), true) {
			return m, nil
		}
		switch msg.String() {
		case "esc":
			if m.flow != nil {
				m.flow.back()
				m.scr = scrFlow
				return m, m.flow.focusCmd()
			}
			m.scr = scrHome
		case "left", "right", "tab", "h", "l":
			if p.ok() {
				p.run = !p.run
			}
		case "enter":
			if p.loading {
				return m, nil
			}
			if !p.ok() {
				// A missing credential binding is approved from the run
				// screen; the run starts once the plan passes.
				if c := approvalFromPlan(p.text); c != nil {
					m.live = newLive(p.opts, m.cfg.Now())
					m.live.initRun(p.text, m.tuis[p.opts.Agent])
					m.live.approval = c
					m.out.Command = optsCommand(p.opts)
					m.scr = scrLive
				}
				return m, nil
			}
			if !p.run {
				m.scr = scrHome
				return m, nil
			}
			m.live = newLive(p.opts, m.cfg.Now())
			m.live.initRun(p.text, m.tuis[p.opts.Agent])
			m.out.Command = optsCommand(p.opts)
			m.scr = scrLive
			return m, m.live.start(m)
		case "a":
			if !p.ok() && !p.loading {
				if agent := approveAgent(p.text); agent != "" {
					return m, approveCmd(agent)
				}
			}
		case "q":
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m model) viewPlan() string {
	p := m.plan
	w := m.w
	var b strings.Builder
	left, right := crumb(recipeName(p.opts.Recipe)), ""
	if m.flow != nil {
		left, right = runCrumbs(m.flow.r, p.opts), trail(m.flow.sections(), "plan")
	}
	b.WriteString(header(w, left, right) + "\n\n")

	// Fixed parts: header (2), box border (2), box title (2), and below
	// the box: buttons (2), command (1), hints (1).
	scH := max(3, m.h-10)
	var body []string
	switch {
	case p.loading:
		body = append(body, sBold.Render("Plan"), "", sAmber.Render(m.spin())+" "+sDim.Render("asking the engine for the plan"))
		for len(body) < scH+2 {
			body = append(body, "")
		}
	default:
		head := sBold.Render("Plan") + "  " + sDim.Render("exactly what will run, nothing has started")
		if !p.ok() {
			head = sBold.Render("Plan refused") + "  " + sDim.Render("the engine stopped before running anything")
		}
		body = append(body, head, "")
		lines := strings.Split(strings.TrimRight(p.text, "\n"), "\n")
		if p.err != nil {
			lines = append(lines, p.err.Error())
		}
		var styled []string
		for _, l := range lines {
			styled = append(styled, planLine(l, p.ok()))
		}
		body = append(body, p.sc.view(styled, w-4, scH)...)
	}
	b.WriteString(box(w, strings.Join(body, "\n")) + "\n")

	if p.ok() {
		run, cancel := "  Run  ", "  Cancel  "
		if p.run {
			run = sSel.Render(run)
			cancel = sDim.Render(cancel)
		} else {
			cancel = sSel.Render(cancel)
			run = sDim.Render(run)
		}
		b.WriteString("\n" + strings.Repeat(" ", 10) + run + "   " + cancel + "\n")
		b.WriteString("  " + sFaint.Render(truncate("same run without the menu: "+optsCommand(p.opts), w-4)) + "\n")
		b.WriteString(hints("enter", "confirm", "←→", "run / cancel", "↑↓ pgup pgdn", "scroll", "w", wrapLabel(p.sc.wrap), "esc", "back"))
	} else {
		if approveAgent(p.text) != "" {
			b.WriteString("\n\n\n" + hints("a", "approve in sbx", "esc", "back", "↑↓", "scroll", "w", wrapLabel(p.sc.wrap), "q", "quit"))
		} else {
			b.WriteString("\n\n\n" + hints("esc", "back", "↑↓", "scroll", "w", wrapLabel(p.sc.wrap), "q", "quit"))
		}
	}
	return b.String()
}

// planLine dims the shell commands of the engine's plan.
func planLine(l string, ok bool) string {
	t := strings.TrimSpace(l)
	switch {
	case !ok:
		return sAmber.Render(l)
	case strings.HasPrefix(t, "$ "):
		return sFaint.Render(l)
	case strings.HasSuffix(t, ":") && !strings.HasPrefix(l, " "):
		return sDim.Render(l)
	case strings.HasPrefix(l, "Plan for"):
		return sText.Render(l)
	}
	return sSoft.Render(l)
}

func wrapLabel(on bool) string {
	if on {
		return "cut lines"
	}
	return "wrap lines"
}
