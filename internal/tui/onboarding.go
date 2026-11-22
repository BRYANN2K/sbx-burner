package tui

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/BRYANN2K/sbx-burner/internal/doctor"
	"github.com/BRYANN2K/sbx-burner/internal/engine"
	"github.com/BRYANN2K/sbx-burner/internal/sanitize"
)

// Setup (first launch and `burner setup`): welcome, machine, agents,
// approvals, preferences, first run, done. Every action runs only on the
// user's key; burner never writes sbx's own files.

// Setup panel layout: lines around the content area (border 2, padding
// 2, blank lines 3, rules 2, keys 1), and the content area's height: the
// tallest step fits in setupContent lines.
const (
	setupChrome  = 10
	setupContent = 20
)

const (
	setupWelcome = iota
	setupMachine
	setupAgents
	setupApprovals
	setupPrefs
	setupFirstRun
	setupDone
)

var sbxVersionRE = regexp.MustCompile(`v[0-9]+\.[0-9]+\.[0-9]+`)

var setupSteps = []string{"machine", "agents", "approvals", "preferences", "first run"}

// setupAgentsList is the agents burner supports, in the order setup shows.
var setupAgentsList = []string{"claude", "codex", "cursor", "devin", "opencode"}

var setupAgentName = map[string]string{"claude": "Claude", "codex": "Codex", "cursor": "Cursor", "devin": "Devin", "opencode": "OpenCode"}

var prefFields = []string{"agent", "model", "mode", "permission", "keep", "runs"}

type setupModel struct {
	step      int
	cursor    int
	field     int
	prefs     Prefs
	models    ModelList
	modelsFor string
	loading   bool
	busy      bool
	note      string
	err       string
	skipped   []string
	sample    string
	awaitRun  bool
	result    string
	chip      int  // the chosen action of a machine line with choices
	advance   bool // move to the next red machine line when the checks return
}

type setupExecDoneMsg struct {
	what string
	err  error
}

type sampleMsg struct {
	path string
	err  error
}

type setupModelsMsg struct {
	agent string
	list  ModelList
}

func sampleDir() string { return expandHome("~/burner-sample") }

func newSetup(p Prefs) *setupModel {
	if p.Agent == "" {
		p.Agent = "codex"
	}
	if p.Mode == "" {
		p.Mode = "acp"
	}
	if p.Permission == "" {
		p.Permission = "auto"
	}
	if p.RunsDir == "" {
		p.RunsDir = "~/.burner/runs"
	}
	return &setupModel{step: setupMachine, cursor: -1, prefs: p, advance: true}
}

// machineCursor resolves the machine step's cursor: -1 means the first
// line that needs action.
func (s *setupModel) machineCursor(rows []doctor.Result) int {
	if len(rows) == 0 {
		return 0
	}
	if s.cursor < 0 || s.cursor >= len(rows) {
		s.cursor = nextRed(rows, 0)
	}
	return s.cursor
}

// setupChecksDone moves the machine cursor to the next line that needs
// action once the checks return after a fix.
func (m model) setupChecksDone() {
	s := m.setup
	if s == nil || s.step != setupMachine || !s.advance {
		return
	}
	rows := m.machineRows()
	if len(rows) == 0 {
		return
	}
	s.advance = false
	from := s.cursor
	if from < 0 || from >= len(rows) {
		from = 0
	}
	s.cursor, s.chip = nextRed(rows, from), 0
}

func (m model) check(id string) (doctor.Result, bool) {
	for _, c := range m.checks {
		if c.ID == id {
			return c, true
		}
	}
	return doctor.Result{}, false
}

// connectCommand is the sbx command that signs an agent in, with the
// sample folder for the ones that sign in inside a sandbox.
func connectCommand(agent string) []string {
	svc, ok := doctor.AgentServices[agent]
	if !ok {
		return nil
	}
	cmd := svc.Fix
	if i := strings.Index(cmd, "  "); i > 0 {
		cmd = cmd[:i]
	}
	cmd = strings.ReplaceAll(cmd, "<folder>", sampleDir())
	return strings.Fields(cmd)
}

func execSetup(what string, argv []string) tea.Cmd {
	if len(argv) == 0 {
		return nil
	}
	return termCmd(what, argv, func(err error) tea.Msg { return setupExecDoneMsg{what, err} })
}

func (m model) setupApprovalRows() []doctor.Result {
	var out []doctor.Result
	for _, c := range m.checks {
		if strings.HasPrefix(c.ID, "approval-") {
			out = append(out, c)
		}
	}
	return out
}

func (m model) loadSetupModels() tea.Cmd {
	s := m.setup
	agent := s.prefs.Agent
	if !contains(m.acpAgents, agent) || (s.modelsFor == agent && !s.loading) {
		return nil
	}
	s.modelsFor, s.loading = agent, true
	ctx, eng := m.ctx, m.eng
	return func() tea.Msg {
		l, _ := eng.Models(ctx, agent)
		return setupModelsMsg{agent, l}
	}
}

// buildSample copies the proving ground's leaky repo (git history with a
// planted, random AWS key pair) to ~/burner-sample/leaky-repo.
func buildSample(ctx context.Context, root string) (string, error) {
	target := filepath.Join(sampleDir(), "leaky-repo")
	if st, err := os.Stat(target); err == nil && st.IsDir() {
		return target, nil
	}
	tmp, err := os.MkdirTemp("", "burner-sample-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "build.sh")
	cmd.Dir = filepath.Join(root, "proving-ground", "devsecops-secrets-scan")
	cmd.Env = append(os.Environ(), "PG_BUILD="+tmp)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("sample build: %s", sanitize.Line(string(out), 200))
	}
	if err := os.MkdirAll(sampleDir(), 0o755); err != nil {
		return "", err
	}
	return target, os.Rename(filepath.Join(tmp, "repo"), target)
}

func (m model) firstRunOpts(path string) engine.RunOptions {
	p := m.setup.prefs
	o := engine.RunOptions{Recipe: "devsecops/secrets-scan", Target: path, Agent: p.Agent, Keep: p.Keep, RunsDir: m.cfg.RunsDir}
	switch p.Mode {
	case "acp":
		if contains(m.acpAgents, p.Agent) {
			o.ACP, o.Model, o.Permission = true, p.Model, p.Permission
		}
	case "interactive":
		o.Interactive, o.Model = true, p.Model
	}
	return o
}

func (m model) updateSetup(msg tea.Msg) (tea.Model, tea.Cmd) {
	s := m.setup
	switch msg := msg.(type) {
	case setupExecDoneMsg:
		s.busy = false
		if msg.err != nil {
			s.err = msg.what + ": " + sanitize.Line(msg.err.Error(), 200)
		}
		m.checking = true
		return m, m.runChecks()
	case approveDoneMsg:
		s.busy = false
		m.checking = true
		return m, m.runChecks()
	case setupModelsMsg:
		if msg.agent == s.modelsFor {
			s.models, s.loading = msg.list, false
		}
		return m, nil
	case sampleMsg:
		s.busy = false
		if msg.err != nil {
			s.err = sanitize.Line(msg.err.Error(), 300)
			return m, nil
		}
		s.sample = msg.path
		o := m.firstRunOpts(msg.path)
		m.live = newLive(o, m.cfg.Now())
		m.live.initRun("", m.tuis[o.Agent])
		s.awaitRun = true
		m.scr = scrLive
		return m, m.live.start(m)
	case tea.KeyMsg:
		return m.keySetup(msg)
	}
	return m, nil
}

func (m model) keySetup(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	s := m.setup
	key := k.String()
	s.err, s.note = "", ""
	if key == "q" && s.step == setupWelcome {
		return m, tea.Quit
	}
	next := func() (tea.Model, tea.Cmd) {
		s.step++
		s.cursor = 0
		if s.step == setupPrefs {
			return m, m.loadSetupModels()
		}
		return m, nil
	}
	switch s.step {
	case setupWelcome:
		if key == "enter" {
			return next()
		}
	case setupMachine:
		rows := m.machineRows()
		cur := s.machineCursor(rows)
		switch key {
		case "up", "k":
			if cur > 0 {
				s.cursor, s.chip = cur-1, 0
			}
		case "down", "j":
			if cur < len(rows)-1 {
				s.cursor, s.chip = cur+1, 0
			}
		case "left", "right":
			if cur < len(rows) && len(rows[cur].Actions) > 1 {
				d := 1
				if key == "left" {
					d = -1
				}
				n := len(rows[cur].Actions)
				s.chip = (s.chip + d + n) % n
			}
		case "enter":
			if cur >= len(rows) || s.busy {
				return m, nil
			}
			if a, ok := pickAction(rows[cur], s.chip); ok && len(a.Argv) > 0 {
				s.busy, s.advance = true, true
				return m, execSetup(machineTitle(rows[cur].ID), a.Argv)
			}
		case "s", "n":
			return next()
		case "esc":
			s.step--
		}
	case setupAgents:
		if key == "esc" {
			s.step, s.cursor = setupMachine, -1
			return m, nil
		}
		switch key {
		case "up":
			if s.cursor > 0 {
				s.cursor--
			}
		case "down":
			if s.cursor < len(setupAgentsList)-1 {
				s.cursor++
			}
		case "enter":
			a := setupAgentsList[s.cursor]
			if a != "opencode" && !s.busy {
				_ = os.MkdirAll(sampleDir(), 0o755)
				s.busy = true
				return m, execSetup("connect "+a, connectCommand(a))
			}
		case "o":
			if !s.busy {
				_ = os.MkdirAll(sampleDir(), 0o755)
				s.busy = true
				return m, execSetup("OpenCode", []string{"sbx", "run", "opencode", sampleDir()})
			}
		case "s", "n":
			return next()
		case "esc":
			s.step--
		}
	case setupApprovals:
		rows := m.setupApprovalRows()
		switch key {
		case "up":
			if s.cursor > 0 {
				s.cursor--
			}
		case "down":
			if s.cursor < len(rows)-1 {
				s.cursor++
			}
		case "a":
			if s.cursor < len(rows) && rows[s.cursor].Level != doctor.OK && !s.busy {
				s.busy = true
				return m, approveCmd(strings.TrimPrefix(rows[s.cursor].ID, "approval-"))
			}
		case "s", "n":
			s.skipped = nil
			for _, r := range rows {
				if r.Level != doctor.OK {
					s.skipped = append(s.skipped, strings.TrimPrefix(r.ID, "approval-"))
				}
			}
			return next()
		case "esc":
			s.step--
		}
	case setupPrefs:
		return m.keySetupPrefs(k)
	case setupFirstRun:
		switch key {
		case "enter":
			if !s.busy && m.cfg.Official {
				s.busy = true
				ctx, root := m.ctx, m.cfg.Root
				return m, func() tea.Msg {
					p, err := buildSample(ctx, root)
					return sampleMsg{p, err}
				}
			}
		case "s":
			s.result = "skipped"
			s.step = setupDone
		case "esc":
			s.step--
		}
	case setupDone:
		if key == "enter" {
			m.setup = nil
			m.scr = scrHome
			return m, nil
		}
	}
	return m, nil
}

func (m model) keySetupPrefs(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	s := m.setup
	p := &s.prefs
	key := k.String()
	field := prefFields[s.field]
	cycle := func(opts []string, cur string, dir int) string {
		i := 0
		for j, o := range opts {
			if o == cur {
				i = j
			}
		}
		return opts[(i+dir+len(opts))%len(opts)]
	}
	dir := 0
	switch key {
	case "tab", "down":
		s.field = (s.field + 1) % len(prefFields)
		return m, nil
	case "shift+tab", "up":
		s.field = (s.field + len(prefFields) - 1) % len(prefFields)
		return m, nil
	case "right":
		dir = 1
	case "left":
		dir = -1
	case "n":
		if field != "runs" {
			if err := SavePrefs(*p); err != nil {
				s.err = sanitize.Line(err.Error(), 200)
				return m, nil
			}
			if d := p.runsDir(); d != "" {
				m.cfg.RunsDir = d
			}
			m.prefs = *p
			s.step = setupFirstRun
			return m, nil
		}
	case "esc":
		s.step--
		return m, nil
	}
	switch field {
	case "agent":
		if dir != 0 {
			p.Agent = cycle(setupAgentsList, p.Agent, dir)
			p.Model = ""
			return m, m.loadSetupModels()
		}
	case "model":
		if dir != 0 {
			vals := []string{""}
			for _, v := range s.models.Values {
				vals = append(vals, v.Value)
			}
			p.Model = cycle(vals, p.Model, dir)
		}
	case "mode":
		if dir != 0 {
			p.Mode = cycle([]string{"acp", "interactive"}, p.Mode, dir)
		}
	case "permission":
		if dir != 0 {
			p.Permission = cycle([]string{"auto", "ask"}, p.Permission, dir)
		}
	case "keep":
		if dir != 0 || key == " " {
			p.Keep = !p.Keep
		}
	case "runs":
		switch k.Type {
		case tea.KeyBackspace:
			if r := []rune(p.RunsDir); len(r) > 0 {
				p.RunsDir = string(r[:len(r)-1])
			}
		case tea.KeyRunes:
			if len(p.RunsDir) < 300 {
				p.RunsDir += string(k.Runes)
			}
		}
	}
	return m, nil
}

func (m model) viewSetup() string {
	s := m.setup
	panelW := m.w - 4
	if panelW > 80 {
		panelW = 80
	}
	if panelW < 40 {
		panelW = 40
	}
	w := panelW - 6 // inside the border and the padding
	var b strings.Builder
	cur := ""
	if s.step-1 < len(setupSteps) && s.step >= 1 {
		cur = setupSteps[s.step-1]
	}
	right := trail(setupSteps, cur)
	if s.step == setupDone {
		right = sSoft.Render("ready")
	}
	if m.checking || s.busy || s.loading {
		right = sAmber.Render(m.spin()) + " " + right
	}
	mark := func(l doctor.Level) string {
		switch l {
		case doctor.OK:
			return sDim.Render("✓")
		case doctor.Fail:
			return sAmber.Render("✗")
		}
		return sAmber.Render("!")
	}
	// row is one line of the mock's 4-column grid: mark, name, value, key.
	row := func(selected bool, mk, name, value, key string) string {
		line := fmt.Sprintf("%s  %-24s %s", mk, name, value)
		if key != "" {
			line += "  " + sDim.Render(key)
		}
		if selected {
			return sel(w, line)
		}
		return line
	}
	cardW := w
	card := func(lines ...string) string { return box(cardW, strings.Join(lines, "\n")) }
	btn := func(k, v string, primary bool) string {
		t := " " + k + " " + v + " "
		if primary {
			return sSel.Render(t)
		}
		return sDim.Render(t)
	}
	var L []string
	var keys []string
	switch s.step {
	case setupMachine:
		rows := m.machineRows()
		cur := s.machineCursor(rows)
		for i, c := range rows {
			v := truncate(c.Detail, w-31)
			if c.ID == "sbx" && c.Level == doctor.OK {
				if f := sbxVersionRE.FindString(v); f != "" {
					v = f
				}
			}
			vs := sDim.Render(v)
			if c.Level != doctor.OK {
				vs = sSoft.Render(v)
			}
			L = append(L, row(i == cur, mark(c.Level), machineTitle(c.ID), vs, ""))
		}
		keys = []string{"↑↓", "move", "n", "next", "esc", "back"}
		if cur < len(rows) {
			if a, ok := pickAction(rows[cur], s.chip); ok {
				c := rows[cur]
				body := []string{sBold.Render(machineTitle(c.ID))}
				if len(c.Actions) > 1 {
					var chips []string
					for i, o := range c.Actions {
						if i == s.chip {
							chips = append(chips, sSel.Render(" "+o.Label+" "))
						} else {
							chips = append(chips, sDim.Render(" "+o.Label+" "))
						}
					}
					body = append(body, strings.Join(chips, " "))
				}
				wrap := lipgloss.NewStyle().Width(cardW - 4)
				switch {
				case len(a.Argv) > 0:
					body = append(body, sSoft.Render(wrap.Render("$ "+actionLine(a))))
				case a.URL != "":
					body = append(body, sSoft.Render(wrap.Render(a.URL)))
				}
				if a.Note != "" {
					note := sDim.Render(a.Note)
					if c.ID == "policy" {
						note = sAmber.Render(a.Note)
					}
					body = append(body, note)
				}
				if len(a.Argv) > 0 {
					body = append(body, "", btn("enter", a.Label, true)+"  "+btn("n", "next", false))
					keys = []string{"↑↓", "move", "enter", a.Label, "n", "next", "esc", "back"}
				}
				if len(c.Actions) > 1 {
					keys = append([]string{"←→", "choose"}, keys...)
				}
				L = append(L, "", card(body...))
			}
		}
	case setupAgents:
		for i, a := range setupAgentsList {
			c, ok := m.check("agent-" + a)
			mk, v, key := sAmber.Render("!"), "not checked", ""
			if ok {
				mk = mark(c.Level)
				v = c.Detail
				if c.Level == doctor.OK {
					v = doctor.AgentServices[a].Service
				}
			}
			if a == "opencode" && ok && c.Level == doctor.OK {
				v = "providers set in OpenCode"
			}
			vs := sDim.Render(v)
			if ok && c.Level != doctor.OK {
				vs = sSoft.Render(v)
			}
			L = append(L, row(i == s.cursor, mk, setupAgentName[a], vs, key))
		}
		a := setupAgentsList[s.cursor]
		c, ok := m.check("agent-" + a)
		keys = []string{"↑↓", "move", "s", "skip", "n", "next", "esc", "back"}
		switch {
		case a == "opencode" && ok && c.Level == doctor.OK:
			keys = []string{"↑↓", "move", "o", "open OpenCode", "s", "skip", "n", "next", "esc", "back"}
		case a == "opencode":
			L = append(L, "", card(sBold.Render("Configure OpenCode"), sSoft.Render("$ sbx run opencode "+tildify(sampleDir())), "",
				btn("o", "open OpenCode", true)+"  "+btn("s", "skip", false)))
			keys = []string{"↑↓", "move", "o", "open OpenCode", "s", "skip", "n", "next", "esc", "back"}
		case !ok || c.Level != doctor.OK:
			if argv := connectCommand(a); len(argv) > 0 {
				L = append(L, "", card(sBold.Render("Connect "+setupAgentName[a]), sSoft.Render("$ "+tildify(strings.Join(argv, " "))), "",
					btn("enter", "connect", true)+"  "+btn("s", "skip", false)))
				keys = []string{"↑↓", "move", "enter", "connect", "s", "skip", "n", "next", "esc", "back"}
			}
		}
	case setupApprovals:
		rows := m.setupApprovalRows()
		for i, r := range rows {
			agent := strings.TrimPrefix(r.ID, "approval-")
			v := strings.ReplaceAll(strings.TrimPrefix(r.Detail, "needs approval: "), ", ", " · ")
			if hosts := strings.Split(strings.TrimPrefix(r.Detail, "needs approval: "), ", "); r.Level != doctor.OK && len(hosts) > 2 {
				v = strings.Join(hosts[:2], " · ") + fmt.Sprintf("  +%d", len(hosts)-2)
			}
			vs := sSoft.Render(v)
			if r.Level == doctor.OK {
				vs = sDim.Render(v)
			}
			L = append(L, row(i == s.cursor, mark(r.Level), setupAgentName[agent]+" kit (kali)", vs, ""))
		}
		if len(rows) == 0 {
			L = append(L, sFaint.Render("none"))
		}
		keys = []string{"↑↓", "move", "s", "skip", "n", "next", "esc", "back"}
		if s.cursor < len(rows) && rows[s.cursor].Level != doctor.OK {
			agent := strings.TrimPrefix(rows[s.cursor].ID, "approval-")
			svc := map[string]string{"claude": "Anthropic", "codex": "OpenAI", "cursor": "Cursor", "devin": "Devin", "opencode": "provider"}[agent]
			hosts := strings.Split(strings.TrimPrefix(rows[s.cursor].Detail, "needs approval: "), ", ")
			body := []string{sBold.Render("Approve your " + svc + " login for burner's " + setupAgentName[agent] + " kit"), ""}
			for _, h := range hosts {
				body = append(body, "  "+sSoft.Render(h))
			}
			body = append(body, "", btn("a", "approve in sbx", true)+"  "+btn("s", "skip", false))
			L = append(L, "", card(body...))
			keys = []string{"↑↓", "move", "a", "approve", "s", "skip", "n", "next", "esc", "back"}
		}
	case setupPrefs:
		p := s.prefs
		chip := func(v string, on bool) string {
			if on {
				return sSel.Render(" " + v + " ")
			}
			return sDim.Render(" " + v + " ")
		}
		label := func(f, t string) string {
			if prefFields[s.field] == f {
				return sAmber.Render(fmt.Sprintf("❯ %-16s", t))
			}
			return sDim.Render(fmt.Sprintf("  %-16s", t))
		}
		var ag []string
		for _, a := range setupAgentsList {
			ag = append(ag, chip(a, a == p.Agent))
		}
		L = append(L, label("agent", "Default agent")+strings.Join(ag, " "), "")
		var ms []string
		vals := []string{""}
		for _, v := range s.models.Values {
			vals = append(vals, v.Value)
		}
		for _, v := range vals {
			name := v
			if name == "" {
				name = "default"
			}
			ms = append(ms, chip(name, v == p.Model))
		}
		if len(ms) > 6 {
			// keep the line short: the current model and its neighbours
			i := 0
			for j, v := range vals {
				if v == p.Model {
					i = j
				}
			}
			lo := i - 2
			if lo < 0 {
				lo = 0
			}
			hi := lo + 5
			if hi > len(ms) {
				hi, lo = len(ms), len(ms)-5
			}
			ms = append(ms[lo:hi:hi], sDim.Render(fmt.Sprintf(" %d models", len(vals)-1)))
		}
		mline := strings.Join(ms, " ")
		switch {
		case s.loading:
			mline += "  " + sAmber.Render(m.spin()) + " " + sDim.Render("asking "+p.Agent+" for its models…")
		case len(s.models.Values) == 0:
			mline += "  " + sDim.Render("full list after the first run")
		}
		L = append(L, label("model", "Model")+mline, "")
		L = append(L, label("mode", "Mode")+chip("ACP", p.Mode == "acp")+" "+chip("Interactive", p.Mode == "interactive"), "")
		L = append(L, label("permission", "Permissions")+chip("auto", p.Permission == "auto")+" "+chip("ask me", p.Permission == "ask"), "")
		L = append(L, label("keep", "After the run")+chip("burn", !p.Keep)+" "+chip("keep", p.Keep), "")
		cursor := ""
		if prefFields[s.field] == "runs" {
			cursor = sAmber.Render("▌")
		}
		L = append(L, label("runs", "Runs folder")+" "+sText.Render(p.RunsDir)+cursor, "", sDim.Render("  saved to  ")+sSoft.Render(tildify(prefsPath())))
		keys = []string{"tab", "next field", "←→", "choose", "n", "next", "esc", "back"}
	case setupFirstRun:
		p := s.prefs
		agent := p.Agent
		if p.Model != "" {
			agent += " · " + p.Model
		}
		agent += " · " + map[string]string{"acp": "ACP", "interactive": "Interactive"}[p.Mode]
		t := ""
		if r, ok := m.recipeByID("devsecops/secrets-scan"); ok {
			t = r.Time
		}
		body := []string{sBold.Render("Try it on a sample project"), "",
			sDim.Render("project   ") + sText.Render(tildify(filepath.Join(sampleDir(), "leaky-repo"))),
			sDim.Render("recipe    ") + sText.Render("devsecops/secrets-scan"),
			sDim.Render("agent     ") + sText.Render(agent)}
		if t != "" {
			body = append(body, sDim.Render("time      ")+sText.Render("~"+t))
		}
		keys = []string{"enter", "copy and run", "s", "skip, finish", "esc", "back"}
		if m.cfg.Official {
			body = append(body, "", btn("enter", "copy + run", true)+"  "+btn("s", "skip", false))
		} else {
			body = append(body, "", sAmber.Render("the sample comes from the official catalog; this catalog is "+tildify(m.cfg.Root)))
			keys = []string{"s", "finish", "esc", "back"}
		}
		L = append(L, card(body...))
	case setupDone:
		mc, _ := m.check("sbx")
		machine := mc.Detail
		if f := sbxVersionRE.FindString(mc.Detail); f != "" {
			machine = "sbx " + f
		}
		if rt, ok := m.check("runtime"); ok {
			machine += " · " + rt.Detail
		}
		if pc, ok := m.check("policy"); ok {
			machine += " · " + pc.Detail
		}
		n := 0
		for _, a := range setupAgentsList {
			if doctor.AgentReady(m.checks, a) {
				n++
			}
		}
		appr := "all approved"
		if need := doctor.ApprovalsNeeded(m.checks); len(need) > 0 {
			appr = strings.Join(need, ", ") + " skipped"
		}
		p := s.prefs
		keep := "burn"
		if p.Keep {
			keep = "keep"
		}
		model := p.Model
		if model == "" {
			model = "default"
		}
		prefs := strings.Join([]string{p.Agent, model, p.Mode, p.Permission, keep}, " · ")
		apprMark := sDim.Render("✓")
		if appr != "all approved" {
			apprMark = sAmber.Render("!")
		}
		first := s.result
		if first == "" {
			first = "skipped"
		}
		machineMark := sDim.Render("✓")
		for _, id := range []string{"brew", "sbx", "runtime", "buildx", "git", "python", "sbx-login", "policy", "disk"} {
			if c, ok := m.check(id); ok && c.Level != doctor.OK {
				machineMark = sAmber.Render("!")
			}
		}
		L = append(L,
			row(false, machineMark, "Machine", sDim.Render(machine), ""),
			row(false, sDim.Render("✓"), "Agents", sDim.Render(fmt.Sprintf("%d connected", n)), ""),
			row(false, apprMark, "Approvals", sDim.Render(appr), ""),
			row(false, sDim.Render("✓"), "Preferences", sDim.Render(prefs), ""),
			row(false, sDim.Render("✓"), "First run", sDim.Render(first), ""),
			"", btn("enter", "open burner", true))
		keys = []string{"enter", "open burner"}
	}
	if s.err != "" {
		L = append(L, "", sAmber.Render(s.err))
	}
	// Header: the logo, then the title, the step and the progress bar.
	stepN, stepName := 0, ""
	for i, st := range setupSteps {
		if st == cur {
			stepN, stepName = i+1, st
		}
	}
	bar := ""
	for i := range setupSteps {
		if i < stepN {
			bar += sAmber.Render("▰")
		} else {
			bar += sFaint.Render("▱")
		}
	}
	title := []string{sBold.Render("burner") + "  " + sDim.Render(m.cfg.Version), "", sSoft.Render("Setup")}
	if s.step == setupDone {
		title = append(title, sAmber.Render("ready"))
	} else {
		title = append(title, sText.Render(strings.ToUpper(stepName[:1])+stepName[1:])+"  "+sDim.Render(fmt.Sprintf("%d of %d", stepN, len(setupSteps))), bar)
	}
	if m.checking || s.busy || s.loading {
		title = append(title, sAmber.Render(m.spin())+" "+sDim.Render("working"))
	}
	rule := sFaint.Render(strings.Repeat("─", w))
	// The panel always fits the terminal and keeps one height on every
	// step. The logo header shows when the full content area fits under
	// it; otherwise a one-line header, and the content area takes what is
	// left.
	contentH, logoH := setupContent, len(m.logoLines())
	head := ""
	if m.h-2-setupChrome-logoH >= setupContent {
		logo := sAmber.Render(strings.Join(m.logoLines(), "\n"))
		head = lipgloss.JoinHorizontal(lipgloss.Top, logo, "    ", lipgloss.NewStyle().Height(logoH).Render(strings.Join(title, "\n")))
	} else {
		if room := m.h - 2 - setupChrome - 1; room < contentH {
			contentH = room
		}
		if contentH < 3 {
			contentH = 3
		}
		line := sBold.Render("burner") + " " + sDim.Render(m.cfg.Version) + sDim.Render(" · ") + sSoft.Render("Setup") + sDim.Render(" · ")
		if s.step == setupDone {
			line += sAmber.Render("ready")
		} else {
			line += sText.Render(strings.ToUpper(stepName[:1])+stepName[1:]) + " " + sDim.Render(fmt.Sprintf("%d of %d", stepN, len(setupSteps))) + " " + bar
		}
		if m.checking || s.busy || s.loading {
			line += "  " + sAmber.Render(m.spin())
		}
		head = line
	}
	lines := strings.Split(strings.Join(L, "\n"), "\n")
	for i, l := range lines {
		if lipgloss.Width(l) > w {
			lines[i] = truncateANSI(l, w) // a wrapped line would change the height
		}
	}
	if len(lines) > contentH {
		lines = lines[:contentH]
	}
	for len(lines) < contentH {
		lines = append(lines, "")
	}
	inner := head + "\n\n" + rule + "\n\n" + strings.Join(lines, "\n") + "\n\n" + rule + "\n" + truncateANSI(strings.TrimLeft(hints(keys...), " "), w)
	panel := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colLine).Padding(1, 2).Width(panelW - 2).Render(inner)
	_ = right
	// The height depends only on the terminal, so the top stays put when a
	// card appears or the step changes.
	top := (m.h - lipgloss.Height(panel)) / 2
	if top < 0 {
		top = 0
	}
	b.WriteString(strings.Repeat("\n", top) + lipgloss.PlaceHorizontal(m.w, lipgloss.Center, panel))
	// Fill below the panel ourselves: fit() keeps a view's last line at
	// the bottom, which would pull the bottom border away from the panel.
	if rest := m.h - top - lipgloss.Height(panel); rest > 0 {
		b.WriteString(strings.Repeat("\n", rest) + " ")
	}
	return b.String()
}

// setupRunDone records the first run's result when its live run ends.
func (m model) setupRunDone() {
	s, l := m.setup, m.live
	if s == nil || !s.awaitRun || l == nil {
		return
	}
	n := 0
	seen := map[string]bool{}
	for _, e := range l.log {
		if e.kind == "finding" && !seen[e.ev.ID] {
			seen[e.ev.ID] = true
			n++
		}
	}
	s.result = fmt.Sprintf("secrets-scan · %s · %s", plural(n, "finding"), clock(l.ended.Sub(l.started)))
	if l.done == nil {
		s.result = fmt.Sprintf("secrets-scan · stopped · exit %d", l.exit)
	}
}
