package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/BRYANN2K/sbx-burner/internal/catalog"
	"github.com/BRYANN2K/sbx-burner/internal/doctor"
)

var targetLabel = map[string]string{
	"path": "folder", "repo": "git repo", "image": "image", "port": "port",
	"url": "url", "app": "running project", "demo": "demo",
}

type homeModel struct {
	recipes []catalog.Recipe
	cats    []string
	planned map[string]bool // categories with planned recipes only
	col     int             // 0 category, 1 recipe
	cat     int
	rec     int
	search  bool
	filter  textinput.Model
	msg     string
}

func newHome(recipes []catalog.Recipe) homeModel {
	h := homeModel{recipes: recipes, planned: map[string]bool{}}
	h.cats = categoryOrder(recipes)
	for _, c := range h.cats {
		h.planned[c] = true
	}
	for _, r := range recipes {
		if r.Runnable() {
			h.planned[catalog.DisplayCategory(r)] = false
		}
	}
	ti := textinput.New()
	ti.Prompt = "/ "
	ti.Placeholder = "search recipes"
	ti.CharLimit = 60
	h.filter = ti
	return h
}

// catOrder is the display order of known categories; others follow
// alphabetically, and categories with planned recipes only come last.
var catOrder = []string{"mine", "devsecops", "pentest", "training", "foundation"}

func categoryOrder(recipes []catalog.Recipe) []string {
	runnable, seen := map[string]bool{}, map[string]bool{}
	for _, r := range recipes {
		c := catalog.DisplayCategory(r)
		seen[c] = true
		if r.Runnable() {
			runnable[c] = true
		}
	}
	rank := func(c string) int {
		for i, k := range catOrder {
			if k == c {
				return i
			}
		}
		return len(catOrder)
	}
	var cats []string
	for c := range seen {
		cats = append(cats, c)
	}
	sort.Slice(cats, func(i, j int) bool {
		a, b := cats[i], cats[j]
		if runnable[a] != runnable[b] {
			return runnable[a]
		}
		if rank(a) != rank(b) {
			return rank(a) < rank(b)
		}
		return a < b
	})
	return cats
}

// list is the recipe column: the category, or every match while searching.
func (h homeModel) list() []catalog.Recipe {
	var out []catalog.Recipe
	q := strings.ToLower(strings.TrimSpace(h.filter.Value()))
	for _, r := range h.recipes {
		if h.search || q != "" {
			if q == "" || strings.Contains(strings.ToLower(r.ID+" "+r.Summary), q) {
				out = append(out, r)
			}
			continue
		}
		if len(h.cats) > 0 && catalog.DisplayCategory(r) == h.cats[h.cat] {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Runnable() != out[j].Runnable() {
			return out[i].Runnable()
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (h homeModel) current() (catalog.Recipe, bool) {
	l := h.list()
	if h.rec < 0 || h.rec >= len(l) {
		return catalog.Recipe{}, false
	}
	return l[h.rec], true
}

func (m model) updateHome(msg tea.Msg) (tea.Model, tea.Cmd) {
	h := &m.home
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	h.msg = ""
	if h.search {
		switch k.String() {
		case "esc":
			h.search = false
			h.filter.SetValue("")
			h.filter.Blur()
			h.rec = 0
			return m, nil
		case "enter":
			h.search = false
			h.filter.Blur()
			h.col = 1
			return m, nil
		case "up", "down":
		default:
			var cmd tea.Cmd
			h.filter, cmd = h.filter.Update(msg)
			h.rec = 0
			return m, cmd
		}
	}
	switch k.String() {
	case "q":
		return m, tea.Quit
	case "/":
		h.search, h.col, h.rec = true, 1, 0
		return m, h.filter.Focus()
	case "d":
		m.scr = scrDoctor
		return m, nil
	case "n":
		m.newr = newNewModel()
		m.scr = scrNew
		return m, nil
	case "u":
		m.out.Action, m.out.Code = "update", 0
		return m, tea.Quit
	case "left", "h":
		if h.filter.Value() == "" {
			h.col = 0
		}
	case "right", "l", "tab":
		h.col = 1
	case "up", "k":
		if h.col == 0 && h.filter.Value() == "" {
			if h.cat > 0 {
				h.cat--
				h.rec = 0
			}
		} else if h.rec > 0 {
			h.rec--
		}
	case "down", "j":
		if h.col == 0 && h.filter.Value() == "" {
			if h.cat < len(h.cats)-1 {
				h.cat++
				h.rec = 0
			}
		} else if h.rec < len(h.list())-1 {
			h.rec++
		}
	case "enter":
		if h.col == 0 && h.filter.Value() == "" {
			h.col = 1
			return m, nil
		}
		r, ok := h.current()
		if !ok {
			return m, nil
		}
		if !r.Runnable() {
			h.msg = r.Name + " is planned: not runnable yet."
			return m, nil
		}
		m.flow = newFlow(r, m.cfg.Cwd, m.checks, m.agents, m.acpAgents)
		m.scr = scrFlow
		return m, m.flow.focusCmd()
	case "esc":
		if h.filter.Value() != "" {
			h.filter.SetValue("")
			h.rec = 0
		}
	}
	return m, nil
}

func (m model) viewHome() string {
	h := m.home
	w := m.w
	var b strings.Builder

	// Top: logo, name, version, working folder. Nothing else.
	b.WriteString(strings.Join(m.headLines(), "\n") + "\n")

	// Columns.
	bodyH := m.h - lipgloss.Height(b.String()) - 1
	if h.msg != "" {
		bodyH--
	}
	if bodyH < 6 {
		bodyH = 6
	}
	catW, recW := 28, 34
	showDetail := w >= 100
	if !showDetail {
		recW = w - catW
	}
	detW := w - catW - recW

	var cl []string
	cl = append(cl, sDim.Render("CATEGORY"))
	for i, c := range h.cats {
		n := 0
		for _, r := range h.recipes {
			if catalog.DisplayCategory(r) == c {
				n++
			}
		}
		label := fmt.Sprintf("%-12s", c) + sDim.Render(fmt.Sprintf("%-3d", n))
		if h.planned[c] {
			label += " " + sFaint.Render("planned")
		}
		if i == h.cat && h.filter.Value() == "" && !h.search {
			if h.col == 0 {
				cl = append(cl, sel(catW-4, "❯ "+label))
			} else {
				cl = append(cl, sText.Render("› "+label))
			}
		} else {
			cl = append(cl, "  "+sSoft.Render(label))
		}
	}

	var rl []string
	if h.search || h.filter.Value() != "" {
		rl = append(rl, h.filter.View())
	} else {
		rl = append(rl, sDim.Render("RECIPE"))
	}
	list := h.list()
	start := 0
	visible := bodyH - 3
	if h.rec >= visible {
		start = h.rec - visible + 1
	}
	for i := start; i < len(list) && i < start+visible; i++ {
		r := list[i]
		name := r.Name
		if h.search || h.filter.Value() != "" {
			name = r.ID
		}
		name = truncate(name, recW-6)
		style := sSoft
		if !r.Runnable() {
			style = sFaint
		}
		if i == h.rec && h.col == 1 {
			rl = append(rl, sel(recW-4, "❯ "+name))
		} else {
			rl = append(rl, "  "+style.Render(name))
		}
	}
	if len(list) == 0 {
		rl = append(rl, sDim.Render("  no match"))
	}

	cols := []string{
		col(catW, bodyH, strings.Join(cl, "\n"), "left"),
		col(recW, bodyH, strings.Join(rl, "\n"), mid(showDetail)),
	}
	if showDetail {
		cols = append(cols, col(detW, bodyH, m.detail(detW-4), "right"))
	}
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, cols...) + "\n")
	if h.msg != "" {
		b.WriteString("  " + sAmber.Render(h.msg) + "\n")
	}
	// Bottom: every command in one bar, then the doctor status line.
	keys := []string{"enter", "run", "/", "search", "d", "doctor", "n", "new recipe", "u", "update", "↑↓ ←→", "move"}
	quit := sSoft.Render("q") + " " + sDim.Render("quit") + " "
	cmds := hints(keys...)
	if lipgloss.Width(cmds)+lipgloss.Width(quit)+2 > w {
		cmds = hintsSep("  ", keys...) // narrow: drop the separators, keep every command
	}
	b.WriteString(header(w, cmds, quit) + "\n")
	b.WriteString(m.statusLine())
	return b.String()
}

func mid(detail bool) string {
	if detail {
		return "mid"
	}
	return "right"
}

// col draws one column of the three-pane browser, joined border to border.
func col(w, h int, body, pos string) string {
	b := lipgloss.RoundedBorder()
	st := lipgloss.NewStyle().Border(b).BorderForeground(colLine).Padding(0, 1).Width(w - 2).Height(h - 2)
	switch pos {
	case "left":
		b.TopRight, b.BottomRight = "┬", "┴"
		st = st.Border(b).BorderRight(false).Width(w - 1)
	case "mid":
		b.TopLeft, b.BottomLeft, b.TopRight, b.BottomRight = "┬", "┴", "┬", "┴"
		st = st.Border(b).BorderRight(false).Width(w - 1)
	case "right":
		b.TopLeft, b.BottomLeft = "┬", "┴"
		st = st.Border(b)
	}
	return st.Render(body)
}

// detailFields are the Detail column's key/value lines. "agents" will
// become "tested with" when recipes stop listing agents.
func detailFields(r catalog.Recipe) [][2]string {
	var ts []string
	for _, t := range r.Targets {
		if l, ok := targetLabel[t]; ok {
			ts = append(ts, l)
		}
	}
	if r.Demo != "" && !r.Accepts("demo") {
		ts = append(ts, "demo")
	}
	scope := map[string]string{"required": "scope file required", "optional": "scope file optional", "none": "none needed"}[r.Scope]
	f := [][2]string{
		{"risk", r.Risk},
		{"time", r.Time},
		{"targets", strings.Join(ts, " · ")},
		{"tested", testedWith(r)},
		{"scope", scope},
	}
	if r.Source != catalog.Official {
		f = append(f, [2]string{"dir", r.Dir})
	}
	return f
}

// detail wraps every field to the column; nothing is cut. Two cells of
// margin absorb characters some terminals draw wide (— ·).
func (m model) detail(w int) string {
	r, ok := m.home.current()
	if !ok {
		return ""
	}
	w -= 2
	status := r.Status
	if status == "" {
		status = "ready"
	}
	var lines []string
	meta := status + " · " + string(r.Source)
	if lipgloss.Width(r.Name)+2+lipgloss.Width(meta) <= w {
		lines = append(lines, sBold.Render(r.Name)+"  "+sDim.Render(meta))
	} else {
		for _, l := range wrap(r.Name, w) {
			lines = append(lines, sBold.Render(l))
		}
		lines = append(lines, sDim.Render(meta))
	}
	lines = append(lines, "")
	for _, l := range wrap(r.Summary, w) {
		lines = append(lines, sSoft.Render(l))
	}
	lines = append(lines, "")
	const keyW = 9
	for _, kv := range detailFields(r) {
		if kv[1] == "" {
			continue
		}
		for i, l := range wrap(kv[1], max(10, w-keyW)) {
			k := ""
			if i == 0 {
				k = kv[0]
			}
			lines = append(lines, sDim.Render(fmt.Sprintf("%-*s", keyW, k))+sText.Render(l))
		}
	}
	return strings.Join(lines, "\n")
}

// statusLine: catalog on the left; sbx, runtime, credentials, disk on the
// right. The spinner turns only while the doctor checks run.
func (m model) statusLine() string {
	left := ""
	var right string
	if m.checking {
		right = sAmber.Render(m.spin()) + sDim.Render(" checking sbx, runtime, disk")
	} else {
		right = sDim.Render(statusSummary(m.checks))
	}
	return header(m.w-2, left, right)
}

func statusSummary(checks []doctor.Result) string {
	get := func(id string) (doctor.Result, bool) {
		for _, c := range checks {
			if c.ID == id {
				return c, true
			}
		}
		return doctor.Result{}, false
	}
	var parts []string
	if c, ok := get("sbx"); ok {
		if c.Level == doctor.OK {
			v := strings.Fields(c.Detail)
			ver := c.Detail
			if len(v) >= 3 {
				ver = strings.TrimPrefix(v[2], "v")
			}
			parts = append(parts, "sbx "+ver)
		} else {
			parts = append(parts, "sbx x")
		}
	}
	if c, ok := get("runtime"); ok {
		if c.Level == doctor.OK {
			parts = append(parts, c.Detail)
		} else {
			parts = append(parts, "no runtime")
		}
	}
	if c, ok := get("disk"); ok {
		parts = append(parts, c.Detail)
	}
	return strings.Join(parts, " │ ")
}

// agentName is the display name of an agent id.
func agentName(a string) string {
	if n, ok := map[string]string{"claude": "Claude Code", "codex": "Codex", "devin": "Devin"}[a]; ok {
		return n
	}
	return a
}

// testedWith is the recipe's optional tested_with list: agents proven by a
// real run. Every runner agent may run any recipe.
func testedWith(r catalog.Recipe) string {
	if len(r.TestedWith) == 0 {
		return "not yet"
	}
	return strings.Join(r.TestedWith, " · ")
}
