package tui

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/BRYANN2K/sbx-burner/internal/catalog"
	"github.com/BRYANN2K/sbx-burner/internal/sandboxes"
	"github.com/BRYANN2K/sbx-burner/internal/sanitize"
)

// sbxList and sbxRemove talk to sbx; tests replace them.
var (
	sbxList   sandboxes.Lister  = sandboxes.SbxList
	sbxRemove sandboxes.Remover = sandboxes.SbxRemove
)

// sandboxesModel lists the sandboxes kept with --keep (burner's own only).
type sandboxesModel struct {
	list    []sandboxes.Kept
	cursor  int
	loading bool
	err     string
	note    string
	from    screen
}

type keptMsg struct {
	list []sandboxes.Kept
	err  error
}

type burnedMsg struct {
	names []string
	err   error
}

func (m model) loadKept() tea.Cmd {
	ctx := m.ctx
	return func() tea.Msg {
		l, err := sandboxes.List(ctx, catalog.Home(), sbxList)
		return keptMsg{l, err}
	}
}

func (m model) openSandboxes(from screen) (model, tea.Cmd) {
	m.sbx = &sandboxesModel{loading: true, from: from}
	m.scr = scrSandboxes
	return m, m.loadKept()
}

func (m model) burn(names ...string) tea.Cmd {
	ctx := m.ctx
	return func() tea.Msg {
		var done []string
		for _, n := range names {
			if err := sandboxes.Burn(ctx, catalog.Home(), n, sbxRemove); err != nil {
				return burnedMsg{done, err}
			}
			done = append(done, n)
		}
		return burnedMsg{done, nil}
	}
}

func (m model) updateSandboxes(msg tea.Msg) (tea.Model, tea.Cmd) {
	s := m.sbx
	switch msg := msg.(type) {
	case keptMsg:
		s.loading = false
		s.list = msg.list
		s.err = ""
		if msg.err != nil {
			s.err = sanitize.Line(msg.err.Error(), 300)
		}
		if s.cursor >= len(s.list) {
			s.cursor = max(0, len(s.list)-1)
		}
		return m, nil
	case burnedMsg:
		if len(msg.names) > 0 {
			s.note = "burned " + strings.Join(msg.names, ", ")
		}
		if msg.err != nil {
			s.err = sanitize.Line(msg.err.Error(), 300)
		}
		s.loading = true
		return m, m.loadKept()
	case agentTUIDoneMsg:
		if msg.err != nil {
			s.err = sanitize.Line(msg.err.Error(), 300)
		}
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if s.cursor > 0 {
				s.cursor--
			}
		case "down", "j":
			if s.cursor < len(s.list)-1 {
				s.cursor++
			}
		case "enter":
			if s.cursor < len(s.list) {
				dir := s.list[s.cursor].RunDir
				m.report = newReport(filepath.Join(dir, "report.md"), dir, filepath.Dir(dir), 0, 0)
				m.scr = scrReport
			}
		case "t":
			if s.cursor < len(s.list) {
				k := s.list[s.cursor]
				if tui := m.tuis[k.Agent]; len(tui) > 0 {
					argv := append([]string{"exec", "-it", k.Name, "--"}, tui...)
					return m, tea.ExecProcess(exec.Command("sbx", argv...), func(err error) tea.Msg { return agentTUIDoneMsg{err} })
				}
			}
		case "b":
			if s.cursor < len(s.list) && !s.loading {
				s.loading = true
				return m, m.burn(s.list[s.cursor].Name)
			}
		case "B":
			if len(s.list) > 0 && !s.loading {
				var names []string
				for _, k := range s.list {
					names = append(names, k.Name)
				}
				s.loading = true
				return m, m.burn(names...)
			}
		case "esc", "q":
			m.scr = scrHome
		}
	}
	return m, nil
}

func (m model) viewSandboxes() string {
	s := m.sbx
	w := m.w
	var b strings.Builder
	right := ""
	if s.loading {
		right = sAmber.Render(m.spin())
	}
	b.WriteString(header(w, sBold.Render("Sandboxes")+sDim.Render(" · kept"), right) + "\n")
	nameW, recW, agW, ageW := 34, 30, 10, 8
	var L []string
	L = append(L, sDim.Render(fmt.Sprintf("  %-*s %-*s %-*s %-*s %s", nameW, "NAME", recW, "RECIPE", agW, "AGENT", ageW, "AGE", "STATE")))
	for i, k := range s.list {
		row := fmt.Sprintf("%-*s %-*s %-*s %-*s %s", nameW, truncate(k.Name, nameW), recW, truncate(k.Recipe, recW), agW, truncate(k.Agent, agW), ageW, sandboxes.Age(k.Created, m.cfg.Now()), k.State)
		if i == s.cursor {
			L = append(L, sel(w-6, "❯ "+row))
		} else {
			L = append(L, "  "+sSoft.Render(row))
		}
	}
	if len(s.list) == 0 && !s.loading {
		L = append(L, "  "+sFaint.Render("none"))
	}
	if s.note != "" {
		L = append(L, "", "  "+sSoft.Render(s.note))
	}
	if s.err != "" {
		L = append(L, "", "  "+sAmber.Render(s.err))
	}
	b.WriteString(box(w, strings.Join(L, "\n")) + "\n")
	b.WriteString(hints("↑↓", "move", "enter", "open run", "t", "agent TUI", "b", "burn", "B", "burn all kept", "esc", "back"))
	return b.String()
}

// recordKept remembers the sandbox of a run kept with --keep.
func recordKept(ctx context.Context, l *liveModel) {
	if !l.opts.Keep || l.runID == "" {
		return
	}
	_ = sandboxes.Add(catalog.Home(), sandboxes.Entry{
		Name:    l.sandboxName(),
		RunDir:  filepath.Join(l.runsDir, l.runID),
		Recipe:  l.opts.Recipe,
		Agent:   l.opts.Agent,
		Created: l.started,
	})
	_ = ctx
}
