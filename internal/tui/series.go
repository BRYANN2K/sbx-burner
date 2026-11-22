package tui

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/BRYANN2K/sbx-burner/internal/catalog"
	"github.com/BRYANN2K/sbx-burner/internal/doctor"
	"github.com/BRYANN2K/sbx-burner/internal/engine"
	"github.com/BRYANN2K/sbx-burner/internal/events"
	"github.com/BRYANN2K/sbx-burner/internal/sanitize"
	"github.com/BRYANN2K/sbx-burner/internal/series"
)

// seriesModel edits the recipes picked on home before they run as a series.
type seriesModel struct {
	items  []series.Item
	cursor int
	name   string
	naming bool
	input  textinput.Model
	note   string
	err    string
}

func (m model) readyAgents() []string {
	var out []string
	for _, a := range m.agents {
		if doctor.AgentReady(m.checks, a) {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		out = m.agents
	}
	return out
}

func (m model) openSeries(items []series.Item, name string) (model, tea.Cmd) {
	ti := textinput.New()
	ti.Prompt = "❯ "
	ti.CharLimit = 63
	m.ser = &seriesModel{items: items, name: name, input: ti}
	m.scr = scrSeries
	return m, m.loadSeriesModels()
}

// newSeriesItems turns the checked recipes into series items, keeping the
// agent and model of an item already edited.
func (m model) newSeriesItems(ids []string) []series.Item {
	prev := map[string]series.Item{}
	if m.ser != nil {
		for _, it := range m.ser.items {
			prev[it.Recipe] = it
		}
	}
	agent := ""
	if ready := m.readyAgents(); len(ready) > 0 {
		agent = ready[0]
		for _, a := range ready {
			if a == "codex" {
				agent = a
			}
		}
	}
	var out []series.Item
	for _, id := range ids {
		if it, ok := prev[id]; ok {
			out = append(out, it)
			continue
		}
		out = append(out, series.Item{Recipe: id, Agent: agent})
	}
	return out
}

type seriesModelsMsg struct {
	agent string
	list  ModelList
}

// loadSeriesModels fetches the model list of every ACP agent in the series
// once (the m key cycles through it).
func (m model) loadSeriesModels() tea.Cmd {
	var cmds []tea.Cmd
	seen := map[string]bool{}
	for _, it := range m.ser.items {
		a := it.Agent
		if seen[a] || !contains(m.acpAgents, a) || m.modelCache[a] != nil {
			continue
		}
		seen[a] = true
		ctx, eng := m.ctx, m.eng
		cmds = append(cmds, func() tea.Msg {
			l, _ := eng.Models(ctx, a)
			return seriesModelsMsg{a, l}
		})
	}
	return tea.Batch(cmds...)
}

func (m model) recipeByID(id string) (catalog.Recipe, bool) {
	r, err := catalog.Find(m.cfg.Recipes, id)
	return r, err == nil
}

func (m model) updateSeries(msg tea.Msg) (tea.Model, tea.Cmd) {
	s := m.ser
	switch msg := msg.(type) {
	case seriesModelsMsg:
		if m.modelCache == nil {
			m.modelCache = map[string]*ModelList{}
		}
		l := msg.list
		m.modelCache[msg.agent] = &l
		return m, nil
	case tea.KeyMsg:
		key := msg.String()
		if s.naming {
			switch key {
			case "esc":
				s.naming = false
			case "enter":
				s.name = strings.TrimSpace(s.input.Value())
				s.naming = false
				p, err := series.Save(catalog.Home(), series.Series{Name: s.name, Items: s.items, Keep: false})
				if err != nil {
					s.err = sanitize.Line(err.Error(), 200)
				} else {
					s.name = series.Slug(s.name)
					s.note = "saved as " + s.name
					s.err = ""
					_ = p
				}
			default:
				var cmd tea.Cmd
				s.input, cmd = s.input.Update(msg)
				return m, cmd
			}
			return m, nil
		}
		var it *series.Item
		if s.cursor < len(s.items) {
			it = &s.items[s.cursor]
		}
		switch key {
		case "up":
			if s.cursor > 0 {
				s.cursor--
			}
		case "down":
			if s.cursor < len(s.items)-1 {
				s.cursor++
			}
		case "left", "right":
			if it != nil {
				ready := m.readyAgents()
				j := 0
				for i, a := range ready {
					if a == it.Agent {
						j = i
					}
				}
				if key == "right" {
					j = (j + 1) % len(ready)
				} else {
					j = (j + len(ready) - 1) % len(ready)
				}
				it.Agent, it.Model = ready[j], ""
				return m, m.loadSeriesModels()
			}
		case "m":
			if it != nil {
				if l := m.modelCache[it.Agent]; l != nil && len(l.Values) > 0 {
					vals := []string{""}
					for _, v := range l.Values {
						vals = append(vals, v.Value)
					}
					j := 0
					for i, v := range vals {
						if v == it.Model {
							j = i
						}
					}
					it.Model = vals[(j+1)%len(vals)]
				}
			}
		case "K":
			if s.cursor > 0 {
				s.items[s.cursor-1], s.items[s.cursor] = s.items[s.cursor], s.items[s.cursor-1]
				s.cursor--
			}
		case "J":
			if s.cursor < len(s.items)-1 {
				s.items[s.cursor+1], s.items[s.cursor] = s.items[s.cursor], s.items[s.cursor+1]
				s.cursor++
			}
		case "d":
			if it != nil {
				s.items = append(s.items[:s.cursor], s.items[s.cursor+1:]...)
				if s.cursor >= len(s.items) && s.cursor > 0 {
					s.cursor--
				}
			}
		case "ctrl+s":
			if len(s.items) > 0 {
				s.naming = true
				s.input.SetValue(s.name)
				return m, s.input.Focus()
			}
		case "esc":
			// Back to home, the selection kept.
			m.home.selMode = true
			m.home.checked = nil
			for _, x := range s.items {
				m.home.checked = append(m.home.checked, x.Recipe)
			}
			m.scr = scrHome
		case "enter":
			if len(s.items) == 0 {
				return m, nil
			}
			first, ok := m.recipeByID(s.items[0].Recipe)
			if !ok {
				return m, nil
			}
			var scopeRecipe *catalog.Recipe
			for _, x := range s.items {
				if r, ok := m.recipeByID(x.Recipe); ok && r.Scope != "none" && r.Scope != "" {
					rr := r
					scopeRecipe = &rr
					break
				}
			}
			m.flow = newFlow(first, m.cfg.Cwd, m.checks, m.agents, m.acpAgents)
			m.flow.series = true
			m.flow.scopeRecipe = scopeRecipe
			m.flow.advance()
			m.scr = scrFlow
			return m, m.flow.focusCmd()
		}
	}
	return m, nil
}

func (m model) viewSeries() string {
	s := m.ser
	w := m.w
	var b strings.Builder
	target := ""
	if len(s.items) > 0 {
		if r, ok := m.recipeByID(s.items[0].Recipe); ok {
			var ks []string
			for _, k := range r.Targets {
				if l, ok := targetLabel[k]; ok {
					ks = append(ks, l)
				}
			}
			target = strings.Join(ks, " · ")
		}
	}
	left := sBold.Render("Series")
	if target != "" {
		left += sDim.Render(" · target " + target)
	}
	b.WriteString(header(w, left, sDim.Render(fmt.Sprintf("%d recipes", len(s.items)))) + "\n")
	firstKinds := map[string]bool{}
	if len(s.items) > 0 {
		if r, ok := m.recipeByID(s.items[0].Recipe); ok {
			for _, k := range r.Targets {
				firstKinds[k] = true
			}
		}
	}
	var L []string
	L = append(L, sDim.Render(fmt.Sprintf("  %-3s %-32s %-9s %-18s", "#", "RECIPE", "AGENT", "MODEL")))
	for i, it := range s.items {
		model := it.Model
		if model == "" {
			model = "default"
		}
		row := fmt.Sprintf("%-3d %-32s %-9s %-18s", i+1, truncate(it.Recipe, 32), truncate(it.Agent, 9), truncate(model, 18))
		extra := ""
		if r, ok := m.recipeByID(it.Recipe); ok {
			shared := false
			for _, k := range r.Targets {
				shared = shared || firstKinds[k]
			}
			if !shared {
				extra += "  " + sRed.Render("no shared target")
			}
			if r.Scope != "none" && r.Scope != "" {
				extra += "  " + sDim.Render("scope")
			}
		}
		if i == s.cursor {
			L = append(L, sel(w-6, "❯ "+row)+extra)
		} else {
			L = append(L, "  "+sSoft.Render(row)+extra)
		}
	}
	if len(s.items) == 0 {
		L = append(L, "  "+sFaint.Render("nothing selected"))
	}
	saved := series.List(catalog.Home())
	if len(saved) > 0 {
		var names []string
		for _, x := range saved {
			names = append(names, x.Name)
		}
		L = append(L, "", "  "+sDim.Render("saved  ")+sSoft.Render(strings.Join(names, " · ")))
	}
	if s.naming {
		L = append(L, "", "  "+sBold.Render("Save as"), "  "+s.input.View())
	}
	if s.note != "" {
		L = append(L, "", "  "+sSoft.Render(s.note))
	}
	if s.err != "" {
		L = append(L, "", "  "+sAmber.Render(s.err))
	}
	b.WriteString(box(w, strings.Join(L, "\n")) + "\n")
	b.WriteString(hints("←→", "agent", "m", "model", "J/K", "move", "d", "remove", "esc", "pick more", "enter", "choose target", "ctrl+s", "save"))
	return b.String()
}

// ---- running a series

type seriesRunModel struct {
	plans    []series.Plan
	rows     []series.RecipeResult
	current  int
	done     bool
	combined series.Combined
	path     string
	err      string
	cancel   context.CancelFunc
	ch       chan tea.Msg
	started  int
	target   string
	scope    string
}

type seriesProgressMsg struct {
	i int
	r series.RecipeResult
}

type seriesDoneMsg struct {
	c    series.Combined
	path string
	err  error
}

// startSeries runs the prepared recipes one after the other with the engine.
func (m model) startSeries(base engine.RunOptions) (model, tea.Cmd) {
	s := series.Series{Name: "series", Items: m.ser.items, OnFailure: "continue"}
	if m.ser.name != "" {
		s.Name = series.Slug(m.ser.name)
	}
	if base.RunsDir == "" {
		base.RunsDir = m.cfg.RunsDir
	}
	plans := series.Prepare(s, m.cfg.Recipes, base, m.acpAgents)
	rows := make([]series.RecipeResult, len(plans))
	for i, p := range plans {
		rows[i] = series.RecipeResult{Recipe: p.Item.Recipe, Agent: p.Item.Agent, Model: p.Item.Model, Status: "queued"}
		if p.Skip != "" {
			rows[i].Status, rows[i].Reason = "skipped", p.Skip
		}
	}
	ctx, cancel := context.WithCancel(m.ctx)
	ch := make(chan tea.Msg, 64)
	r := &seriesRunModel{plans: plans, rows: rows, cancel: cancel, ch: ch, target: targetLabelOf(base), scope: base.Scope}
	m.srun = r
	m.scr = scrSeriesRun
	eng := m.eng
	run := func(ctx context.Context, o engine.RunOptions) (string, int, error) {
		report := ""
		code, err := eng.Run(ctx, o, func(e events.Event) {
			if e.Type == "done" {
				report = e.Report
			}
		}, &tail{max: 50})
		return report, code, err
	}
	go func() {
		c, path, err := series.Run(ctx, s, plans, targetLabelOf(base), base.RunsDir, run, func(i int, res series.RecipeResult) {
			ch <- seriesProgressMsg{i, res}
		})
		ch <- seriesDoneMsg{c, path, err}
		close(ch)
	}()
	return m, waitCh(ch)
}

func (m model) updateSeriesRun(msg tea.Msg) (tea.Model, tea.Cmd) {
	r := m.srun
	switch msg := msg.(type) {
	case seriesProgressMsg:
		if msg.i < len(r.rows) {
			r.rows[msg.i] = msg.r
			r.current = msg.i
		}
		return m, waitCh(r.ch)
	case seriesDoneMsg:
		r.done, r.combined, r.path = true, msg.c, msg.path
		if msg.err != nil {
			r.err = sanitize.Line(msg.err.Error(), 300)
		}
		m.out.Code, m.out.Report = 0, msg.path
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			if r.done {
				return m, tea.Quit
			}
			r.cancel()
		case "enter":
			if r.done {
				m.scr = scrSeriesReport
			}
		case "h":
			if r.done {
				m.scr = scrHome
			}
		}
	}
	return m, nil
}

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func (m model) viewSeriesRun() string {
	r := m.srun
	w := m.w
	var b strings.Builder
	left := sBold.Render("Series") + sDim.Render(" · "+r.target)
	if r.scope != "" {
		left += sDim.Render(" · " + tildify(r.scope))
	}
	right := sAmber.Render(m.spin()) + sDim.Render(" running")
	if r.done {
		right = sBold.Render("■ done")
	}
	b.WriteString(header(w, left, right) + "\n")
	var L []string
	for i, x := range r.rows {
		mark := " "
		state := sDim.Render(x.Status)
		switch x.Status {
		case "running":
			mark = sAmber.Render(m.spin())
		case "done":
			mark = sDim.Render("✓")
			state = sDim.Render(plural(x.Findings, "finding"))
		case "skipped":
			mark = sRed.Render("–")
			state = sRed.Render(x.Reason)
		case "failed":
			mark = sAmber.Render("✗")
			state = sAmber.Render("failed " + x.Reason)
		}
		model := x.Model
		if model == "" {
			model = "default"
		}
		row := fmt.Sprintf("%-3d %-32s %-9s %-18s", i+1, truncate(x.Recipe, 32), truncate(x.Agent, 9), truncate(model, 18))
		L = append(L, mark+" "+sSoft.Render(row)+"  "+state)
	}
	if r.done {
		L = append(L, "", sBold.Render(plural(len(r.combined.Findings), "finding")+" · combined report written"), sDim.Render(tildify(r.path)))
	}
	if r.err != "" {
		L = append(L, "", sAmber.Render(r.err))
	}
	b.WriteString(box(w, strings.Join(L, "\n")) + "\n")
	if r.done {
		b.WriteString(hints("enter", "combined report", "h", "home"))
	} else {
		b.WriteString(hints("ctrl+c", "stop series"))
	}
	return b.String()
}

func (m model) updateSeriesReport(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "o":
			openPath(m.srun.path, m.cfg.RunsDir, false)
		case "enter", "esc":
			m.scr = scrHome
		case "q":
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m model) viewSeriesReport() string {
	r := m.srun
	w := m.w
	var b strings.Builder
	b.WriteString(header(w, sBold.Render("■ series report")+sDim.Render(" · "+r.target), "") + "\n")
	L := []string{sDim.Render("FINDINGS · MERGED")}
	for _, f := range r.combined.Findings {
		sev := sSoft
		switch f.Severity {
		case "critical", "high":
			sev = sRed
		case "medium":
			sev = sAmber
		case "low", "info":
			sev = sDim
		}
		left := sev.Render(fmt.Sprintf("%-9s", f.Severity)) + " " + sText.Render(sanitize.Line(f.Title, 200))
		L = append(L, header(w-6, left, sDim.Render(strings.Join(f.Sources, " · "))))
	}
	if len(r.combined.Findings) == 0 {
		L = append(L, sFaint.Render("none"))
	}
	L = append(L, "", sDim.Render("PER RECIPE"))
	for _, x := range r.combined.Recipes {
		right := x.Status
		if x.Report != "" {
			right = tildify(x.Report)
		} else if x.Reason != "" {
			right = x.Status + " · " + x.Reason
		}
		L = append(L, header(w-6, sText.Render(x.Recipe), sDim.Render(right)))
	}
	b.WriteString(box(w, strings.Join(L, "\n")) + "\n")
	b.WriteString(hints("o", "open report.md", "enter", "home", "q", "quit"))
	return b.String()
}
