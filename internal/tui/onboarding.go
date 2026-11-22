package tui

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/BRYANN2K/sbx-burner/internal/doctor"
	"github.com/BRYANN2K/sbx-burner/internal/engine"
	"github.com/BRYANN2K/sbx-burner/internal/sanitize"
)

// Setup (first launch and `burner setup`): welcome, machine, agents,
// approvals, preferences, first run, done. Every action runs only on the
// user's key; burner never writes sbx's own files.

const (
	setupWelcome = iota
	setupMachine
	setupAgents
	setupApprovals
	setupPrefs
	setupFirstRun
	setupDone
)

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
	return &setupModel{prefs: p}
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
	return tea.ExecProcess(exec.Command(argv[0], argv[1:]...), func(err error) tea.Msg { return setupExecDoneMsg{what, err} })
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
		switch key {
		case "enter":
			if c, ok := m.check("policy"); ok && c.Level != doctor.OK && !s.busy {
				s.busy = true
				return m, execSetup("sbx policy init", strings.Fields(doctor.PolicyInitCommand))
			}
		case "s", "n":
			return next()
		case "esc":
			s.step--
		}
	case setupAgents:
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
			if _, blocked := doctor.Blocked[a]; blocked {
				return m, nil
			}
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
	w := m.w
	var b strings.Builder
	if s.step == setupWelcome {
		logo := m.logoLines()
		lines := []string{}
		for i, l := range logo {
			row := sAmber.Render(l)
			switch i {
			case 3:
				row += "   " + sBold.Render("burner") + "  " + sDim.Render(m.cfg.Version)
			case 5:
				row += "   " + sSoft.Render("Run coding agents on your projects")
			case 6:
				row += "   " + sSoft.Render("inside Docker Sandboxes.")
			}
			lines = append(lines, row)
		}
		b.WriteString("\n" + box(w, strings.Join(lines, "\n")) + "\n")
		b.WriteString(hints("enter", "set up", "q", "quit"))
		return b.String()
	}
	cur := ""
	if s.step-1 < len(setupSteps) && s.step >= 1 {
		cur = setupSteps[s.step-1]
	}
	right := trail(setupSteps, cur)
	title := "Setup"
	if s.step == setupDone {
		title, right = "Setup", sSoft.Render("ready")
	}
	if m.checking || s.busy || s.loading {
		right = sAmber.Render(m.spin()) + " " + right
	}
	b.WriteString(header(w, sBold.Render(title), right) + "\n")
	mark := func(l doctor.Level) string {
		switch l {
		case doctor.OK:
			return sDim.Render("✓")
		case doctor.Fail:
			return sAmber.Render("✗")
		}
		return sAmber.Render("!")
	}
	row := func(sel_ bool, m_, name, detail string) string {
		line := fmt.Sprintf("%s  %-30s %s", m_, name, detail)
		if sel_ {
			return sel(w-6, line)
		}
		return line
	}
	var L []string
	var keys []string
	switch s.step {
	case setupMachine:
		for _, id := range []string{"sbx", "runtime", "buildx", "policy", "disk", "git-login"} {
			if c, ok := m.check(id); ok {
				L = append(L, row(false, mark(c.Level), c.Title, sDim.Render(c.Detail)))
			}
		}
		keys = []string{"n", "next"}
		if c, ok := m.check("policy"); ok && c.Level != doctor.OK {
			L = append(L, "", sBold.Render("Global network policy"), "  "+sText.Render("$ "+doctor.PolicyInitCommand), "  "+sAmber.Render("changes the global sbx policy: every sbx sandbox on this Mac, not only burner's"))
			keys = []string{"enter", "run the command", "s", "skip", "n", "next"}
		}
	case setupAgents:
		for i, a := range setupAgentsList {
			c, ok := m.check("agent-" + a)
			mk, detail := sAmber.Render("!"), "not checked"
			if ok {
				mk, detail = mark(c.Level), c.Detail
			}
			L = append(L, row(i == s.cursor, mk, setupAgentName[a], sDim.Render(detail)))
		}
		a := setupAgentsList[s.cursor]
		if a == "opencode" {
			L = append(L, "", sBold.Render("Configure OpenCode"), "  "+sText.Render("$ sbx run opencode "+tildify(sampleDir())))
			keys = []string{"↑↓", "move", "o", "open OpenCode", "s", "skip", "n", "next", "esc", "back"}
		} else if why, blocked := doctor.Blocked[a]; blocked {
			L = append(L, "", sAmber.Render(setupAgentName[a]+": "+why))
			keys = []string{"↑↓", "move", "s", "skip", "n", "next", "esc", "back"}
		} else {
			if argv := connectCommand(a); len(argv) > 0 {
				L = append(L, "", sBold.Render("Connect "+setupAgentName[a]), "  "+sText.Render("$ "+tildify(strings.Join(argv, " "))))
			}
			keys = []string{"↑↓", "move", "enter", "connect", "s", "skip", "n", "next", "esc", "back"}
		}
	case setupApprovals:
		rows := m.setupApprovalRows()
		for i, r := range rows {
			L = append(L, row(i == s.cursor, mark(r.Level), r.Title, sDim.Render(r.Detail)))
		}
		if len(rows) == 0 {
			L = append(L, sFaint.Render("none"))
		}
		keys = []string{"↑↓", "move", "a", "approve in sbx", "s", "skip", "n", "next", "esc", "back"}
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
				return sAmber.Render("❯ " + t)
			}
			return sDim.Render("  " + t)
		}
		var ag []string
		for _, a := range setupAgentsList {
			ag = append(ag, chip(a, a == p.Agent))
		}
		L = append(L, label("agent", "Default agent"), "    "+strings.Join(ag, " "), "")
		model := "default"
		if p.Model != "" {
			model = p.Model
		}
		mline := "    " + chip(model, true)
		if s.loading {
			mline += "  " + sAmber.Render(m.spin()) + " " + sDim.Render("asking "+p.Agent+" for its models…")
		} else if len(s.models.Values) > 0 {
			mline += "  " + sDim.Render(fmt.Sprintf("%d models", len(s.models.Values)))
		}
		L = append(L, label("model", "Model"), mline, "")
		L = append(L, label("mode", "Mode"), "    "+chip("ACP", p.Mode == "acp")+" "+chip("Interactive", p.Mode == "interactive"), "")
		L = append(L, label("permission", "Permissions"), "    "+chip("auto", p.Permission == "auto")+" "+chip("ask me", p.Permission == "ask"), "")
		L = append(L, label("keep", "After the run"), "    "+chip("burn", !p.Keep)+" "+chip("keep", p.Keep), "")
		cursor := ""
		if prefFields[s.field] == "runs" {
			cursor = sAmber.Render("▌")
		}
		L = append(L, label("runs", "Runs folder"), "    "+sText.Render(p.RunsDir)+cursor, "", sDim.Render("SAVED TO  ")+sSoft.Render(tildify(prefsPath())))
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
		L = append(L, sBold.Render("Try it on a sample project"), "",
			sDim.Render("project   ")+sText.Render(tildify(filepath.Join(sampleDir(), "leaky-repo"))),
			sDim.Render("recipe    ")+sText.Render("devsecops/secrets-scan"),
			sDim.Render("agent     ")+sText.Render(agent))
		if t != "" {
			L = append(L, sDim.Render("time      ")+sText.Render("~"+t))
		}
		keys = []string{"enter", "copy and run", "s", "skip, finish", "esc", "back"}
		if !m.cfg.Official {
			L = append(L, "", sAmber.Render("the sample comes from the official catalog; this catalog is "+tildify(m.cfg.Root)))
			keys = []string{"s", "finish", "esc", "back"}
		}
	case setupDone:
		mc, _ := m.check("sbx")
		machine := mc.Detail
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
			appr = strings.Join(need, ", ") + " kit skipped"
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
		for _, id := range []string{"sbx", "runtime", "buildx", "policy", "disk"} {
			if c, ok := m.check(id); ok && c.Level != doctor.OK {
				machineMark = sAmber.Render("!")
			}
		}
		L = append(L,
			row(false, machineMark, "Machine", sDim.Render(machine)),
			row(false, sDim.Render("✓"), "Agents", sDim.Render(fmt.Sprintf("%d connected", n))),
			row(false, apprMark, "Approvals", sDim.Render(appr)),
			row(false, sDim.Render("✓"), "Preferences", sDim.Render(prefs)),
			row(false, sDim.Render("✓"), "First run", sDim.Render(first)),
			"", sDim.Render("burner setup to run it again"))
		keys = []string{"enter", "open burner"}
	}
	if s.err != "" {
		L = append(L, "", sAmber.Render(s.err))
	}
	b.WriteString(box(w, strings.Join(L, "\n")) + "\n")
	b.WriteString(hints(keys...))
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
