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
	qForm // the scope form, on its own screen
)

type option struct {
	label, value, note string
	disabled           bool // shown faint, cannot be picked
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
	wait        string // shown with a spinner under the options, which stay usable
	warn        string // one line under the options
	loader      string // what startLoad runs: models | scope-dry
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
	inflight    map[string]bool

	prefs       Prefs           // setup's defaults (~/.burner/config.yaml)
	series      bool            // a series: target (and scope) only
	scopeRecipe *catalog.Recipe // the series recipe whose scope template is used

	models        ModelList
	modelsFor     string
	modelsLoading bool
	modelsProbing bool            // asking the agent in a throwaway sandbox
	modelsErr     string          // the probe's failure (sign-in hint)
	probed        map[string]bool // agents already probed in this flow
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
// sections is the header trail: only the steps that apply to this recipe
// and to the answers so far.
func (f *flowModel) sections() []string {
	s := []string{"target"}
	if f.series {
		if f.scopeRecipe != nil {
			s = append(s, "scope")
		}
		return append(s, "run")
	}
	if f.r.Scope != "none" && f.r.Scope != "" {
		s = append(s, "scope")
	}
	s = append(s, "agent", "mode")
	o, _ := f.script(&walker{ans: f.answers})
	acpOK := contains(f.acp, o.Agent)
	if acpOK && (o.ACP || o.Interactive || !f.modeAnswered()) {
		s = append(s, "model")
	}
	if o.ACP || (acpOK && !f.modeAnswered()) {
		s = append(s, "permissions")
	}
	return append(s, "notes", "plan")
}

// modeAnswered reports whether the Mode question is behind us.
func (f *flowModel) modeAnswered() bool {
	for _, a := range f.answers {
		if a.title == "Mode" {
			return true
		}
	}
	return false
}

// trail renders the header trail, the current step in amber.
func trail(steps []string, cur string) string {
	idx := -1
	for i, s := range steps {
		if s == cur {
			idx = i
		}
	}
	parts := make([]string, len(steps))
	for i, s := range steps {
		switch {
		case i == idx:
			parts[i] = sAmber.Render(s)
		case i < idx:
			parts[i] = sSoft.Render(s)
		default:
			parts[i] = sFaint.Render(s)
		}
	}
	return strings.Join(parts, sFaint.Render(" › "))
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

	// Scope (in a series: when one of its recipes needs one).
	scopeMode := r.Scope
	if f.series {
		scopeMode = "none"
		if f.scopeRecipe != nil {
			scopeMode = "required"
		}
	}
	if scopeMode == "required" || scopeMode == "optional" {
		use := "yes"
		if scopeMode == "optional" {
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

	if f.series {
		return o, true
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
		disabled := false
		if !doctor.AgentReady(f.checks, a) {
			note = "no credential · " + svc.Fix
		} else if def < 0 {
			def = len(aopts)
		}
		if f.checks == nil && !disabled {
			note = ""
		}
		aopts = append(aopts, option{label: agentName(a), value: a, note: note, disabled: disabled})
	}
	if len(aopts) == 0 {
		w.ask(question{section: "agent", title: "Agent", kind: qSelect, hint: "The runner reported no agent burner supports yet."})
		return
	}
	if def < 0 {
		def = 0
		for i, op := range aopts {
			if !op.disabled {
				def = i
				break
			}
		}
	}
	if f.prefs.Agent != "" {
		for i, op := range aopts {
			if op.value == f.prefs.Agent && !op.disabled {
				def = i
			}
		}
	}
	o.Agent = aopts[def].value
	if len(aopts) > 1 || aopts[0].disabled {
		v, ok := w.ask(question{section: "agent", title: "Agent", kind: qSelect, options: aopts, cursor: def})
		if !ok {
			return
		}
		o.Agent = v
	}

	// Mode: ACP when burner can drive the agent, Interactive (the agent's
	// own TUI) always, Headless when ACP is not wired for it.
	acpOK := contains(f.acp, o.Agent)
	var mopts []option
	if acpOK {
		mopts = append(mopts, option{label: "ACP", value: "acp", note: "burner drives the agent, live view and chat"})
	} else {
		mopts = append(mopts, option{label: "Headless", value: "headless", note: "one prompt, live view"})
	}
	mopts = append(mopts, option{label: "Interactive", value: "interactive", note: "the agent's own TUI in the sandbox"})
	mode, ok := w.ask(question{section: "mode", title: "Mode", kind: qSelect, options: mopts, cursor: optIndex(mopts, f.prefs.Mode)})
	if !ok {
		return
	}
	o.ACP, o.Interactive = mode == "acp", mode == "interactive"
	if acpOK && (o.ACP || o.Interactive) {
		if f.modelsFor != o.Agent || f.modelsLoading {
			w.ask(question{section: "model", title: "Model", loader: "models", loading: "asking " + o.Agent + " for its models…"})
			return
		}
		ml := f.models
		def := "default"
		if ml.Current != "" {
			def = ml.Current
		}
		mo := []option{{label: "Agent default", value: "", note: def}}
		for _, md := range ml.Values {
			if md.Value != "" {
				mo = append(mo, option{label: md.Value, value: md.Value, note: md.Name})
			}
		}
		q := question{section: "model", title: "Model", kind: qSelect, options: mo, cursor: optIndex(mo, f.prefs.Model)}
		if f.modelsProbing {
			q.wait = "asking " + o.Agent + " for its models… (first time ~1 min)"
		} else if f.modelsErr != "" {
			q.warn = f.modelsErr
		}
		mdl, ok := w.ask(q)
		if !ok {
			return
		}
		o.Model = mdl
	}
	if o.ACP {
		popts := []option{
			{label: "auto", value: "auto", note: "allow once, every grant logged"},
			{label: "ask me", value: "ask"},
		}
		perm, ok := w.ask(question{section: "permissions", title: "Permissions", kind: qSelect, options: popts, cursor: optIndex(popts, f.prefs.Permission)})
		if !ok {
			return
		}
		o.Permission = perm
	}

	// Notes.
	v, ok := w.ask(question{section: "notes", title: "Notes for the agent", kind: qNotes})
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
			v, ok := f.projectPath(w)
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
	rcp := f.r
	if f.series && f.scopeRecipe != nil {
		rcp = *f.scopeRecipe
		o.Recipe = rcp.EngineRef()
	}
	key := scopeKey(o)
	if f.scopeDry == nil || f.scopeDryKey != key {
		w.ask(question{section: "scope", title: "Scope", loader: "scope-dry", loadKey: "dry\x00" + key, loadOpts: o, loading: "preparing a scope from your target…"})
		return "", false
	}
	var opts []option
	hint := ""
	if f.scopeDry.Error == "" {
		opts = append(opts, option{label: "Build the scope", value: "build", note: summaryLine(f.scopeDry.Summary)})
	} else {
		hint = "cannot create one: " + sanitize.Line(f.scopeDry.Error, 200)
	}
	saved := savedScopes(rcp)
	if len(saved) > 0 {
		opts = append(opts, option{label: "Reuse a saved scope", value: "saved", note: fmt.Sprintf("%d in ~/.burner/scopes", len(saved))})
	}
	opts = append(opts, option{label: "Browse…", value: "browse"}, option{label: "Type a path", value: "type"})
	how, ok := w.ask(question{section: "scope", title: "Scope file", hint: hint, kind: qSelect, options: opts})
	if !ok {
		return "", false
	}
	switch how {
	case "build":
		return w.ask(question{section: "scope", title: "Scope", kind: qForm})
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

// projectMarkers are files that make a folder look like an app project.
var projectMarkers = []string{"package.json", "pyproject.toml", "requirements.txt", "go.mod", "Cargo.toml", "Gemfile", "pom.xml", "build.gradle", "composer.json", "manage.py", "deno.json"}

func looksLikeProject(dir string) bool {
	for _, m := range projectMarkers {
		if st, err := os.Stat(filepath.Join(dir, m)); err == nil && st.Mode().IsRegular() {
			return true
		}
	}
	return false
}

// burnerFolder: the cwd holds a burner catalog or a runs folder, so it is
// not the app (copying it would copy the runs too).
func burnerFolder(dir string) bool {
	for _, m := range []string{"runs", "recipes"} {
		if st, err := os.Stat(filepath.Join(dir, m)); err == nil && st.IsDir() {
			return true
		}
	}
	return false
}

// projectPath asks for the app folder: sub-folders that look like
// projects first, "This folder" only when the cwd is a project and not a
// burner folder.
func (f *flowModel) projectPath(w *walker) (string, bool) {
	var opts []option
	here := option{label: "This folder (" + f.cwd + ")", value: "here"}
	hereOK := !burnerFolder(f.cwd)
	if hereOK && looksLikeProject(f.cwd) {
		opts = append(opts, here)
	}
	if entries, err := os.ReadDir(f.cwd); err == nil {
		for _, e := range entries {
			name := e.Name()
			if !e.IsDir() || strings.HasPrefix(name, ".") || name == "runs" || name == "node_modules" {
				continue
			}
			dir := filepath.Join(f.cwd, name)
			if !looksLikeProject(dir) {
				continue
			}
			note := ""
			if a, ok := appdetect.Detect(dir); ok {
				note = a.Stack
			}
			opts = append(opts, option{label: name + "/", value: dir, note: note})
			if len(opts) >= 12 {
				break
			}
		}
	}
	opts = append(opts, option{label: "Browse…", value: "browse"}, option{label: "Type a path", value: "type"})
	hint := ""
	if !hereOK {
		hint = "this folder holds burner's runs or catalog, so it is not offered"
	} else if !looksLikeProject(f.cwd) {
		opts = append(opts, here)
	}
	how, ok := w.ask(question{section: "target", title: "Project folder", hint: hint, kind: qSelect, options: opts})
	if !ok {
		return "", false
	}
	if filepath.IsAbs(how) {
		return how, true
	}
	return f.pathHow(w, "target", "Project folder", how, true, false, nil)
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
	probe  bool   // the answer of ProbeModels, not of the cache
	err    string // the probe's failure
}

// probeModels asks the agent itself when nothing is cached; "default"
// stays selectable meanwhile.
func (m model) probeModels(agent string) tea.Cmd {
	ctx, eng := m.ctx, m.eng
	return func() tea.Msg {
		ms, err := eng.ProbeModels(ctx, agent)
		msg := modelsMsg{agent: agent, models: ms, probe: true}
		if err != nil {
			msg.err = ms.Error
			if msg.err == "" {
				msg.err = sanitize.Line(err.Error(), 200)
			}
		}
		return msg
	}
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
		}
		f.advance()
		return m, tea.Batch(f.focusCmd(), m.startLoad())
	}
	if mm, ok := msg.(modelsMsg); ok {
		var probe tea.Cmd
		if mm.agent == f.modelsFor {
			cursor, title := f.cursor, ""
			if f.q != nil {
				title = f.q.title
			}
			f.models, f.modelsLoading = mm.models, false
			switch {
			case mm.probe:
				f.modelsProbing, f.modelsErr = false, mm.err
				if mm.err != "" {
					f.models = ModelList{}
				}
			case !mm.models.Known && !f.probed[mm.agent]:
				if f.probed == nil {
					f.probed = map[string]bool{}
				}
				f.probed[mm.agent], f.modelsProbing, f.modelsErr = true, true, ""
				probe = m.probeModels(mm.agent)
			}
			f.advance()
			// The list grew under the user's cursor: keep it on "default"
			// or wherever it was, not on the preference.
			if mm.probe && f.q != nil && f.q.title == title && title == "Model" && cursor < len(f.q.options) {
				f.cursor = cursor
			}
		}
		return m, tea.Batch(f.focusCmd(), probe)
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
			if o.disabled {
				return m, nil
			}
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
	return m.afterAnswer()
}

// afterAnswer moves on once a question is answered: the plan when the flow
// is complete, a loader, the scope form, or the next question.
func (m model) afterAnswer() (tea.Model, tea.Cmd) {
	f := m.flow
	if f.q == nil {
		if f.series {
			return m.startSeries(f.opts)
		}
		if m.prefs.Keep {
			f.opts.Keep = true
		}
		m.plan = newPlan(f.opts)
		m.scr = scrPlan
		return m, m.plan.start(m)
	}
	if f.q.loading != "" {
		return m, m.startLoad()
	}
	if f.q.kind == qForm && f.scopeDry != nil {
		m.form = newScopeForm(f.scopeDry.Scope, catalog.DisplayCategory(f.r)+"/"+f.r.Name, "", m.cfg.Now())
		m.scr = scrScopeForm
		return m, nil
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
	cur := "plan"
	if f.q != nil {
		cur = f.q.section
	}
	o, _ := f.script(&walker{ans: f.answers})
	b.WriteString(header(w, runCrumbs(f.r, o), trail(f.sections(), cur)) + "\n\n")

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
			switch {
			case i == f.cursor:
				body = append(body, sel(inner-2, "❯ "+line))
			case o.disabled:
				body = append(body, "  "+sFaint.Render(line))
			default:
				body = append(body, "  "+sSoft.Render(line))
			}
		}
		if q.wait != "" {
			body = append(body, "", sAmber.Render(m.spin())+" "+sDim.Render(q.wait))
		}
		if q.warn != "" {
			body = append(body, "", sAmber.Render(truncate(q.warn, inner-2)))
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

// runCrumbs is the header's left side: category/recipe · target · agent.
func runCrumbs(r catalog.Recipe, o engine.RunOptions) string {
	out := sBold.Render(catalog.DisplayCategory(r) + "/" + r.Name)
	if t := targetLabelOf(o); t != "" {
		out += sDim.Render(" · " + t)
	}
	if o.Agent != "" {
		out += sDim.Render(" · " + o.Agent)
	}
	return out
}

// targetLabelOf names the chosen target in one short phrase.
func targetLabelOf(o engine.RunOptions) string {
	switch {
	case o.TargetURL != "":
		return o.TargetURL
	case o.TargetApp != "":
		return tildify(o.TargetApp)
	case o.TargetImage != "":
		if o.TargetPort != "" {
			return o.TargetImage + " :" + o.TargetPort
		}
		return o.TargetImage
	case o.TargetRepo != "":
		return o.TargetRepo
	case o.Target != "":
		return tildify(o.Target)
	}
	return ""
}

// optIndex is the option whose value is v, else the first one.
func optIndex(opts []option, v string) int {
	for i, o := range opts {
		if v != "" && o.value == v {
			return i
		}
	}
	return 0
}

// check returns a doctor line by id.
func (f *flowModel) check(id string) (doctor.Result, bool) {
	for _, c := range f.checks {
		if c.ID == id {
			return c, true
		}
	}
	return doctor.Result{}, false
}
