package tui

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/BRYANN2K/sbx-burner/internal/appdetect"
	"github.com/BRYANN2K/sbx-burner/internal/catalog"
	"github.com/BRYANN2K/sbx-burner/internal/doctor"
	"github.com/BRYANN2K/sbx-burner/internal/engine"
	"github.com/BRYANN2K/sbx-burner/internal/sanitize"
)

// The flow asks only what the chosen recipe needs: target, scope, agent,
// (mode and model when the engine drives agents over ACP), notes. It is a
// script replayed over the answers so far, so going back is dropping the
// last answer.

type qKind int

const (
	qSelect qKind = iota
	qInput
	qBrowse
	qNotes
	qPreview
)

type option struct {
	label, value, note string
}

type question struct {
	section     string
	title       string
	hint        string
	kind        qKind
	options     []option
	cursor      int // default option
	placeholder string
	initial     string
	validate    func(string) error
	dirs, files bool
	types       []string
	loading     string // shown with a spinner instead of the question
	loader      string // what startLoad runs: models | scope-dry | scope-create
	loadKey     string
	loadOpts    engine.RunOptions
	loadRef     string
}

type answer struct {
	title, value, shown string
}

type flowModel struct {
	r      catalog.Recipe
	cwd    string
	checks []doctor.Result
	agents []string // every agent the runner can launch
	acp    []string // agents burner drives over ACP

	answers []answer
	q       *question
	opts    engine.RunOptions

	cursor int
	input  textinput.Model
	notes  textarea.Model
	br     *browser
	err    string

	scopeDry    *ScopeResult // scope new --dry-run for scopeDryKey
	scopeDryKey string
	scopeRes    *ScopeResult // the created scope for scopeResKey
	scopeResKey string
	scopeBusy   bool // checking the scope after an edit
	inflight    map[string]bool

	models        ModelList
	modelsFor     string
	modelsLoading bool
}

// walker hands out recorded answers in order, then records the first
// unanswered question.
type walker struct {
	ans     []answer
	i       int
	pending *question
}

func (w *walker) ask(q question) (string, bool) {
	if w.pending != nil {
		return "", false
	}
	if w.i < len(w.ans) {
		v := w.ans[w.i].value
		w.i++
		return v, true
	}
	w.pending = &q
	return "", false
}

var kindLabel = map[string]string{
	"app":   "Running project (npm, python, go…)",
	"path":  "Local folder or files",
	"repo":  "GitHub or git repo",
	"image": "Docker image (local or registry)",
	"url":   "URL",
}

func newFlow(r catalog.Recipe, cwd string, checks []doctor.Result, agents, acp []string) *flowModel {
	f := &flowModel{r: r, cwd: cwd, checks: checks, agents: agents, acp: acp, inflight: map[string]bool{}}
	f.advance()
	return f
}

// sections in order, for the step dots.
func (f *flowModel) sections() []string {
	s := []string{"recipe", "target"}
	if f.r.Scope != "none" && f.r.Scope != "" {
		s = append(s, "scope")
	}
	return append(s, "agent", "plan", "run")
}

func (f *flowModel) script(w *walker) (o engine.RunOptions, done bool) {
	r := f.r
	o.Recipe = r.EngineRef()

	// Target.
	if r.TargetMode != "none" {
		var kinds []option
		for _, k := range []string{"app", "path", "repo", "image", "url"} {
			if r.Accepts(k) {
				kinds = append(kinds, option{label: kindLabel[k], value: k})
			}
		}
		if len(kinds) > 0 {
			kind := kinds[0].value
			if len(kinds) > 1 {
				v, ok := w.ask(question{section: "target", title: "Where is your target?", kind: qSelect, options: kinds})
				if !ok {
					return
				}
				kind = v
			}
			if !f.target(w, kind, &o) {
				return
			}
		}
	}

	// Scope.
	if r.Scope == "required" || r.Scope == "optional" {
		use := "yes"
		if r.Scope == "optional" {
			v, ok := w.ask(question{section: "scope", title: "Use a scope file?", kind: qSelect,
				options: []option{{label: "No", value: "no"}, {label: "Yes", value: "yes"}}})
			if !ok {
				return
			}
			use = v
		}
		if use == "yes" {
			v, ok := f.scopeStep(w, o)
			if !ok {
				return
			}
			o.Scope = v
		}
	}

	// Agent.
	// Every agent the runner can launch; recipes no longer restrict it.
	agents := f.agents
	if len(agents) == 0 {
		agents = doctor.KnownAgents()
	}
	var aopts []option
	def := -1
	for _, a := range agents {
		svc, ok := doctor.AgentServices[a]
		if !ok {
			continue
		}
		note := "credential stored"
		if !doctor.AgentReady(f.checks, a) {
			note = "no credential · " + svc.Fix
		} else if def < 0 {
			def = len(aopts)
		}
		if f.checks == nil {
			note = ""
		}
		aopts = append(aopts, option{label: agentName(a), value: a, note: note})
	}
	if len(aopts) == 0 {
		w.ask(question{section: "agent", title: "Agent", kind: qSelect, hint: "The runner reported no agent burner supports yet."})
		return
	}
	if def < 0 {
		def = 0
	}
	o.Agent = aopts[def].value
	if len(aopts) > 1 {
		v, ok := w.ask(question{section: "agent", title: "Agent", kind: qSelect, options: aopts, cursor: def})
		if !ok {
			return
		}
		o.Agent = v
	}

	// Mode, model and permissions: only for agents burner drives over ACP.
	if contains(f.acp, o.Agent) {
		v, ok := w.ask(question{section: "agent", title: "Mode", kind: qSelect, options: []option{
			{label: "ACP", value: "acp", note: "live view, permissions, model choice"},
			{label: "Headless", value: "headless", note: "one prompt, no conversation"},
		}})
		if !ok {
			return
		}
		if v == "acp" {
			o.ACP = true
			if f.modelsFor != o.Agent || f.modelsLoading {
				w.ask(question{section: "agent", title: "Model", loader: "models", loading: "asking " + o.Agent + " for its models…"})
				return
			}
			ml := f.models
			def := "the agent's default"
			if ml.Current != "" {
				def = ml.Current
			}
			mo := []option{{label: "Agent default", value: "", note: def}}
			for _, md := range ml.Values {
				if md.Value == "" {
					continue
				}
				label := md.Value
				note := md.Name
				if md.Value == ml.Current {
					note += "  (default)"
				}
				mo = append(mo, option{label: label, value: md.Value, note: note})
			}
			hint := "listed by " + o.Agent
			if !ml.Known {
				hint = o.Agent + " has not listed its models yet; it uses its default"
			}
			mdl, ok := w.ask(question{section: "agent", title: "Model", hint: hint, kind: qSelect, options: mo})
			if !ok {
				return
			}
			o.Model = mdl
			perm, ok := w.ask(question{section: "agent", title: "Permissions", kind: qSelect, options: []option{
				{label: "Auto", value: "auto", note: "allow inside the sandbox, every decision logged"},
				{label: "Ask me", value: "ask", note: "you approve each action here"},
			}})
			if !ok {
				return
			}
			o.Permission = perm
		}
	}

	// Notes.
	v, ok := w.ask(question{section: "agent", title: "Notes for the agent (optional)", kind: qNotes})
	if !ok {
		return
	}
	if s := strings.TrimSpace(v); s != "" {
		o.Prompts = []string{s}
	}
	return o, true
}

func (f *flowModel) target(w *walker, kind string, o *engine.RunOptions) bool {
	switch kind {
	case "path":
		v, ok := f.path(w, "target", "Folder or files to test", true, true, nil, "")
		o.Target = v
		return ok
	case "repo":
		v, ok := w.ask(question{section: "target", title: "Repo", kind: qInput,
			placeholder: "owner/repo or owner/repo@branch", hint: "Private repos are cloned on this Mac with your git login.", validate: nonEmpty})
		o.TargetRepo = v
		return ok
	case "url":
		v, ok := w.ask(question{section: "target", title: "URL", kind: qInput, placeholder: "https://staging.example.com", validate: nonEmpty})
		o.TargetURL = v
		return ok
	case "image":
		how, ok := w.ask(question{section: "target", title: "Image", kind: qSelect, options: []option{
			{label: "Image name (local or registry)", value: "ref"},
			{label: "Tarball file (docker save / container image save)", value: "tar"},
		}})
		if !ok {
			return false
		}
		if how == "tar" {
			v, ok := f.path(w, "target", "Image tarball", false, true, []string{".tar", ".tgz", ".gz", ".oci"}, "")
			if !ok {
				return false
			}
			o.TargetImage = v
		} else {
			v, ok := w.ask(question{section: "target", title: "Image", kind: qInput, placeholder: "ghcr.io/you/app:1.0", validate: nonEmpty})
			if !ok {
				return false
			}
			o.TargetImage = v
		}
		if f.r.Accepts("port") {
			v, ok := w.ask(question{section: "target", title: "Port", hint: "Empty to scan the image only.", kind: qInput, placeholder: "8080", validate: portOrEmpty})
			if !ok {
				return false
			}
			o.TargetPort = v
		}
		return true
	case "app":
		where, ok := w.ask(question{section: "target", title: "Project", kind: qSelect, options: []option{
			{label: "Local folder", value: "local"},
			{label: "GitHub or git repo", value: "repo"},
		}})
		if !ok {
			return false
		}
		hint := ""
		if where == "local" {
			v, ok := f.path(w, "target", "Project folder", true, false, nil, "")
			if !ok {
				return false
			}
			o.TargetApp = v
			if a, found := appdetect.Detect(v); found {
				o.AppInstall, o.AppCmd, o.AppPort = a.Install, a.Start, strconv.Itoa(a.Port)
				hint = "Detected " + a.Stack + " · install: " + a.Install
			}
		} else {
			v, ok := w.ask(question{section: "target", title: "Repo", kind: qInput, placeholder: "owner/repo or owner/repo@branch", validate: nonEmpty})
			if !ok {
				return false
			}
			o.TargetApp = v
		}
		v, ok := w.ask(question{section: "target", title: "Start command", hint: hint, kind: qInput, placeholder: "npm run dev", initial: o.AppCmd, validate: nonEmpty})
		if !ok {
			return false
		}
		o.AppCmd = v
		v, ok = w.ask(question{section: "target", title: "Port", kind: qInput, placeholder: "3000", initial: o.AppPort, validate: port})
		if !ok {
			return false
		}
		o.AppPort = v
		return true
	}
	return true
}

// scopeStep: create a scope from the target (preview, edit), reuse a saved
// one, browse, or type a path.
func (f *flowModel) scopeStep(w *walker, o engine.RunOptions) (string, bool) {
	key := scopeKey(o)
	if f.scopeDry == nil || f.scopeDryKey != key {
		w.ask(question{section: "scope", title: "Scope", loader: "scope-dry", loadKey: "dry\x00" + key, loadOpts: o, loading: "preparing a scope from your target…"})
		return "", false
	}
	var opts []option
	hint := ""
	if f.scopeDry.Error == "" {
		opts = append(opts, option{label: "Create from my target", value: "create", note: summaryLine(f.scopeDry.Summary)})
	} else {
		hint = "cannot create one: " + sanitize.Line(f.scopeDry.Error, 200)
	}
	saved := savedScopes(f.r)
	if len(saved) > 0 {
		opts = append(opts, option{label: "Reuse a saved scope", value: "saved", note: fmt.Sprintf("%d in ~/.burner/scopes", len(saved))})
	}
	opts = append(opts, option{label: "Browse…", value: "browse"}, option{label: "Type a path", value: "type"})
	how, ok := w.ask(question{section: "scope", title: "Scope file", hint: hint, kind: qSelect, options: opts})
	if !ok {
		return "", false
	}
	switch how {
	case "create":
		ref := ""
		if f.scopeDry.Summary.Auth == "written" {
			ref, ok = w.ask(question{section: "scope", title: "Written authorization", kind: qInput,
				hint:        "Link or id of the written authorization for " + strings.Join(f.scopeDry.Summary.Hosts, ", ") + ".",
				placeholder: "https://… or a contract id", validate: nonEmpty})
			if !ok {
				return "", false
			}
		}
		ckey := key + "\x00" + ref
		if f.scopeRes == nil || f.scopeResKey != ckey {
			w.ask(question{section: "scope", title: "Scope", loader: "scope-create", loadKey: "create\x00" + ckey, loadOpts: o, loadRef: ref, loading: "writing the scope…"})
			return "", false
		}
		return w.ask(question{section: "scope", title: "Scope preview", kind: qPreview})
	case "saved":
		var so []option
		for _, p := range saved {
			so = append(so, option{label: filepath.Base(p), value: p})
		}
		return w.ask(question{section: "scope", title: "Saved scopes", hint: "~/.burner/scopes", kind: qSelect, options: so})
	default:
		return f.pathHow(w, "scope", "Scope file", how, false, true, []string{".yaml", ".yml"})
	}
}

// path asks: this folder, browse, or type a path.
func (f *flowModel) path(w *walker, section, title string, dirs, files bool, types []string, hint string) (string, bool) {
	var opts []option
	if dirs {
		opts = append(opts, option{label: "This folder (" + f.cwd + ")", value: "here"})
	}
	opts = append(opts, option{label: "Browse…", value: "browse"}, option{label: "Type a path", value: "type"})
	how, ok := w.ask(question{section: section, title: title, hint: hint, kind: qSelect, options: opts})
	if !ok {
		return "", false
	}
	return f.pathHow(w, section, title, how, dirs, files, types)
}

// pathHow asks the path itself once "here", "browse" or "type" is chosen.
func (f *flowModel) pathHow(w *walker, section, title, how string, dirs, files bool, types []string) (string, bool) {
	switch how {
	case "here":
		return f.cwd, true
	case "browse":
		return w.ask(question{section: section, title: title, kind: qBrowse, dirs: dirs, files: files, types: types})
	default:
		validate := existsPath
		if !dirs {
			validate = existsFile
		}
		return w.ask(question{section: section, title: title, kind: qInput, placeholder: "./", validate: validate})
	}
}

// advance replays the answers and sets up the widget for the next question.
func (f *flowModel) advance() {
	w := &walker{ans: f.answers}
	o, done := f.script(w)
	if done {
		f.q, f.opts = nil, o
		return
	}
	f.q = w.pending
	f.err = ""
	if f.q == nil {
		return
	}
	switch f.q.kind {
	case qSelect:
		f.cursor = f.q.cursor
	case qInput:
		ti := textinput.New()
		ti.Prompt = "❯ "
		ti.Placeholder = f.q.placeholder
		ti.SetValue(f.q.initial)
		ti.CharLimit = 2048
		ti.Focus()
		f.input = ti
	case qBrowse:
		f.br = newBrowser(f.cwd, f.q.dirs, f.q.files, f.q.types)
	case qNotes:
		ta := textarea.New()
		ta.Placeholder = "What should the agent focus on?"
		ta.ShowLineNumbers = false
		ta.SetPromptFunc(2, func(i int) string {
			if i == 0 {
				return "❯ "
			}
			return "  "
		})
		ta.CharLimit = 8192
		ta.SetHeight(3)
		ta.KeyMap.InsertNewline = key.NewBinding(key.WithKeys("alt+enter"))
		ta.Focus()
		f.notes = ta
	}
}

func (f *flowModel) focusCmd() tea.Cmd {
	if f.q != nil && (f.q.kind == qInput || f.q.kind == qNotes) {
		return textinput.Blink
	}
	return nil
}

func (f *flowModel) record(value, shown string) {
	f.answers = append(f.answers, answer{title: f.q.title, value: value, shown: shown})
	f.advance()
}

func (f *flowModel) back() bool {
	if len(f.answers) == 0 {
		return false
	}
	f.answers = f.answers[:len(f.answers)-1]
	f.advance()
	return true
}

type modelsMsg struct {
	agent  string
	models ModelList
}

func (m model) updateFlow(msg tea.Msg) (tea.Model, tea.Cmd) {
	f := m.flow
	switch mm := msg.(type) {
	case scopeMsg:
		delete(f.inflight, mm.key)
		res := mm.res
		if mm.err != nil && res.Error == "" && res.Path == "" {
			res.Error = mm.err.Error()
		}
		switch mm.kind {
		case "dry":
			f.scopeDry, f.scopeDryKey = &res, strings.TrimPrefix(mm.key, "dry\x00")
		case "create":
			f.scopeRes, f.scopeResKey = &res, strings.TrimPrefix(mm.key, "create\x00")
		case "check":
			f.scopeBusy = false
			if f.scopeRes != nil && f.scopeResKey == mm.key {
				res.Notes = f.scopeRes.Notes
				f.scopeRes = &res
			}
			return m, nil
		}
		f.advance()
		return m, tea.Batch(f.focusCmd(), m.startLoad())
	case editedMsg:
		if f.scopeRes != nil && f.scopeRes.Path == mm.path {
			f.scopeBusy = true
			return m, m.checkScope(mm.path, f.scopeResKey)
		}
		return m, nil
	}
	if mm, ok := msg.(modelsMsg); ok {
		if mm.agent == f.modelsFor {
			f.models, f.modelsLoading = mm.models, false
			f.advance()
		}
		return m, f.focusCmd()
	}
	k, isKey := msg.(tea.KeyMsg)
	if f.q == nil {
		return m, nil
	}
	if f.q.loading != "" {
		if isKey && k.String() == "esc" {
			f.back()
		}
		return m, m.startLoad()
	}
	if !isKey {
		var cmd tea.Cmd
		switch f.q.kind {
		case qInput:
			f.input, cmd = f.input.Update(msg)
		case qNotes:
			f.notes, cmd = f.notes.Update(msg)
		}
		return m, cmd
	}
	if k.String() == "esc" {
		if !f.back() {
			m.scr = scrHome
		}
		return m, f.focusCmd()
	}
	switch f.q.kind {
	case qSelect:
		switch k.String() {
		case "up", "k":
			if f.cursor > 0 {
				f.cursor--
			}
		case "down", "j":
			if f.cursor < len(f.q.options)-1 {
				f.cursor++
			}
		case "enter":
			if len(f.q.options) == 0 {
				return m, nil
			}
			o := f.q.options[f.cursor]
			f.record(o.value, o.label)
		case "q":
			return m, tea.Quit
		}
	case qInput:
		if k.String() == "enter" {
			v := strings.TrimSpace(f.input.Value())
			if f.q.validate != nil {
				if err := f.q.validate(v); err != nil {
					f.err = err.Error()
					return m, nil
				}
			}
			f.record(v, v)
			break
		}
		var cmd tea.Cmd
		f.input, cmd = f.input.Update(msg)
		f.err = ""
		return m, cmd
	case qPreview:
		switch k.String() {
		case "enter":
			if f.scopeBusy || f.scopeRes == nil {
				return m, nil
			}
			if !f.scopeRes.Valid {
				f.err = "fix what is listed first: e opens the file"
				return m, nil
			}
			f.record(f.scopeRes.Path, f.scopeRes.Path)
		case "e":
			if f.scopeRes != nil && f.scopeRes.Path != "" && !f.scopeBusy {
				return m, editScope(f.scopeRes.Path)
			}
		case "q":
			return m, tea.Quit
		}
	case qBrowse:
		var p string
		var picked bool
		switch k.String() {
		case "up", "k":
			f.br.up()
		case "down", "j":
			f.br.down()
		case "left", "h", "backspace":
			f.br.parent()
		case "right", "l":
			if f.br.cursor < len(f.br.entries) && f.br.entries[f.br.cursor].dir {
				f.br.enter()
			}
		case "enter":
			p, picked = f.br.enter()
		case " ":
			p, picked = f.br.pick()
		case ".":
			p, picked = f.br.pickHere()
		case "H":
			f.br.toggleHidden()
		case "q":
			return m, tea.Quit
		}
		if picked {
			f.record(p, p)
		}
	case qNotes:
		if k.String() == "enter" {
			v := strings.TrimSpace(f.notes.Value())
			shown := v
			if shown == "" {
				shown = "none"
			}
			f.record(v, shown)
			break
		}
		var cmd tea.Cmd
		f.notes, cmd = f.notes.Update(msg)
		return m, cmd
	}
	if f.q == nil {
		m.plan = newPlan(f.opts)
		m.scr = scrPlan
		return m, m.plan.start(m)
	}
	if f.q.loading != "" {
		return m, m.startLoad()
	}
	return m, f.focusCmd()
}

func (m model) loadModels() tea.Cmd {
	f := m.flow
	w := &walker{ans: f.answers}
	o, _ := f.script(w)
	agent := o.Agent
	if f.modelsLoading && f.modelsFor == agent {
		return nil
	}
	f.modelsFor, f.modelsLoading, f.models = agent, true, ModelList{}
	ctx, eng := m.ctx, m.eng
	return func() tea.Msg {
		ms, _ := eng.Models(ctx, agent)
		return modelsMsg{agent: agent, models: ms}
	}
}

func (m model) viewFlow() string {
	f := m.flow
	w := m.w
	var b strings.Builder
	secs := f.sections()
	cur := "plan"
	if f.q != nil {
		cur = f.q.section
	}
	idx := 0
	for i, s := range secs {
		if s == cur {
			idx = i
		}
	}
	parts := []string{catalog.DisplayCategory(f.r), f.r.Name}
	b.WriteString(header(w, crumb(parts...), stepDots(idx+1, len(secs), cur)) + "\n\n")

	for _, a := range f.answers {
		if a.value == "browse" || a.value == "type" {
			continue // the path answer that follows says it all
		}
		b.WriteString("  " + sDim.Render(a.title+"  ") + sSoft.Render(truncate(a.shown, w-lipgloss.Width(a.title)-6)) + "\n")
	}
	if len(f.answers) > 0 {
		b.WriteString("\n")
	}
	if f.q == nil {
		return b.String()
	}
	q := f.q
	inner := w - 4
	var body []string
	title := sBold.Render(q.title)
	if q.hint != "" && q.kind != qInput {
		title += "  " + sDim.Render(q.hint)
	}
	body = append(body, title, "")
	switch {
	case q.loading != "":
		body = append(body, sAmber.Render(m.spin())+" "+sDim.Render(q.loading))
	case q.kind == qSelect:
		for i, o := range q.options {
			line := o.label
			if o.note != "" {
				pad := 30 - lipgloss.Width(o.label)
				if pad < 2 {
					pad = 2
				}
				line += strings.Repeat(" ", pad) + sDim.Render(o.note)
			}
			if i == f.cursor {
				body = append(body, sel(inner-2, "❯ "+line))
			} else {
				body = append(body, "  "+sSoft.Render(line))
			}
		}
	case q.kind == qInput:
		if q.hint != "" {
			body = append(body, sDim.Render(q.hint))
		}
		body = append(body, f.input.View())
		if f.err != "" {
			body = append(body, sAmber.Render(f.err))
		}
	case q.kind == qBrowse:
		body = append(body, f.br.view(inner-2, m.h-lipgloss.Height(b.String())-5))
	case q.kind == qNotes:
		f.notes.SetWidth(inner - 2)
		body = append(body, f.notes.View())
	case q.kind == qPreview && f.scopeRes != nil:
		body = append(body, previewLines(*f.scopeRes, inner-2)...)
		if f.scopeBusy {
			body = append(body, "", sAmber.Render(m.spin())+" "+sDim.Render("checking the scope"))
		}
		if f.err != "" {
			body = append(body, "", sAmber.Render(f.err))
		}
	}
	b.WriteString(box(w, strings.Join(body, "\n")) + "\n")

	switch {
	case q.kind == qBrowse:
		keys := []string{"↑↓", "move", "enter", "open", "←", "parent", "H", "hidden"}
		if q.dirs {
			keys = append(keys, "space", "select", ".", "this folder")
		} else {
			keys = append(keys, "enter", "select file")
		}
		b.WriteString(hints(append(keys, "esc", "back")...))
	case q.kind == qNotes:
		b.WriteString(hints("enter", "continue", "opt+enter", "newline", "esc", "back"))
	case q.kind == qPreview:
		b.WriteString(hints("enter", "use", "e", "edit in $EDITOR", "esc", "back"))
	case q.kind == qInput:
		b.WriteString(hints("enter", "continue", "esc", "back", "ctrl+c", "quit"))
	default:
		b.WriteString(hints("↑↓", "move", "enter", "select", "esc", "back", "ctrl+c", "quit"))
	}
	return b.String()
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func nonEmpty(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("required")
	}
	return nil
}

func port(s string) error {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return errors.New("a port between 1 and 65535")
	}
	return nil
}

func portOrEmpty(s string) error {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return port(s)
}

func existsPath(s string) error {
	if _, err := os.Stat(strings.TrimSpace(s)); err != nil {
		return errors.New("not found")
	}
	return nil
}

func existsFile(s string) error {
	st, err := os.Stat(strings.TrimSpace(s))
	if err != nil || st.IsDir() {
		return errors.New("file not found")
	}
	return nil
}
