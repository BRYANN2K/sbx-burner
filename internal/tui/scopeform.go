package tui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/BRYANN2K/sbx-burner/internal/engine"
	"github.com/BRYANN2K/sbx-burner/internal/sanitize"
)

// Risky techniques, off by default (lab/scope.py RISKY); checking one
// writes it under techniques.risky.
var riskyTechs = []string{"brute-force", "lockout-testing", "credential-reuse", "dos", "ddos", "data-destruction", "social-engineering", "phishing", "physical", "ransomware"}

var formFields = []string{"name", "targets", "auth", "days", "techs", "out", "net"}

type techRow struct {
	name string
	on   bool
}

// scopeForm is the scope form: it edits a scope document and keeps every
// field it does not show (notes, test accounts, extra targets).
type scopeForm struct {
	doc     map[string]any
	path    string // scope edit: the file to replace
	title   string // category/recipe, or the file name
	field   int
	name    string
	targets []string
	auth    string
	ref     string
	days    int
	techs   []techRow
	risky   []techRow
	tcur    int // cursor in techs then risky
	out     []string
	net     string // strict | standard
	owner   string
	adding  string // "targets" | "out" | "export"
	input   textinput.Model
	busy    bool
	errs    []string
	note    string
	today   time.Time
}

func newScopeForm(doc map[string]any, title, path string, today time.Time) *scopeForm {
	f := &scopeForm{doc: cloneDoc(doc), title: title, path: path, auth: "own-lab", days: 30, net: "strict", today: today}
	get := func(m any, k string) any {
		mm, _ := m.(map[string]any)
		return mm[k]
	}
	strs := func(v any) []string {
		xs, _ := v.([]any)
		var out []string
		for _, x := range xs {
			if s, ok := x.(string); ok {
				out = append(out, sanitize.Line(s, 200))
			}
		}
		return out
	}
	f.name, _ = f.doc["id"].(string)
	f.owner, _ = f.doc["owner"].(string)
	if t, ok := get(f.doc["authorization"], "type").(string); ok {
		f.auth = t
	}
	if r, ok := get(f.doc["authorization"], "reference").(string); ok && !strings.Contains(r, "TODO(burner)") {
		f.ref = r
	}
	if a, err := time.Parse("2006-01-02", fmt.Sprint(get(f.doc["valid"], "not_before"))); err == nil {
		if b, err := time.Parse("2006-01-02", fmt.Sprint(get(f.doc["valid"], "not_after"))); err == nil {
			if d := int(b.Sub(a).Hours() / 24); d > 0 {
				f.days = d
			}
		}
	}
	if targets, ok := f.doc["targets"].([]any); ok {
		for _, t := range targets {
			if h := get(t, "hosts"); h != nil {
				f.targets = strs(h)
				break
			}
		}
	}
	if get(f.doc["network"], "mode") == "additive" {
		f.net = "standard"
	}
	f.out = strs(get(f.doc["network"], "deny"))
	allowed := strs(get(f.doc["techniques"], "allowed"))
	forbidden := strs(get(f.doc["techniques"], "forbidden"))
	isRisky := map[string]bool{}
	for _, r := range riskyTechs {
		isRisky[r] = true
	}
	seen := map[string]bool{}
	for _, t := range allowed {
		if !isRisky[t] && !seen[t] {
			seen[t] = true
			f.techs = append(f.techs, techRow{t, true})
		}
	}
	for _, t := range forbidden {
		if !isRisky[t] && !seen[t] {
			seen[t] = true
			f.techs = append(f.techs, techRow{t, false})
		}
	}
	for _, r := range riskyTechs {
		on := false
		for _, a := range allowed {
			on = on || a == r
		}
		f.risky = append(f.risky, techRow{r, on})
	}
	ti := textinput.New()
	ti.Prompt = "❯ "
	ti.CharLimit = 300
	f.input = ti
	return f
}

func cloneDoc(d map[string]any) map[string]any {
	b, _ := json.Marshal(d)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	if out == nil {
		out = map[string]any{}
	}
	return out
}

// peopleTechs need written authorization even against a local target.
var peopleTechs = map[string]bool{"social-engineering": true, "phishing": true, "physical": true}

// sandboxLocal: localhost, 127.0.0.0/8 or ::1, with or without a port.
func sandboxLocal(h string) bool {
	host := h
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[:i], ":") {
		host = h[:i]
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" || host == "::1" {
		return true
	}
	return strings.HasPrefix(host, "127.")
}

var slugRE = regexp.MustCompile(`[^a-z0-9]+`)

func slug(s string) string {
	return strings.Trim(slugRE.ReplaceAllString(strings.ToLower(s), "-"), "-")
}

// valid is the form's own check; the engine validates again on save.
func (f *scopeForm) problems() []string {
	var p []string
	if slug(f.name) == "" {
		p = append(p, "a name")
	}
	if len(f.targets) == 0 {
		p = append(p, "a target host")
	}
	if f.auth == "written" && strings.TrimSpace(f.ref) == "" {
		p = append(p, "a reference")
	}
	if f.auth != "written" {
		local := true
		for _, h := range f.targets {
			local = local && sandboxLocal(h)
		}
		for _, t := range f.risky {
			if t.on && (peopleTechs[t.name] || !local) {
				p = append(p, "written authorization for "+t.name)
			}
		}
	}
	on := 0
	for _, t := range append(append([]techRow{}, f.techs...), f.risky...) {
		if t.on {
			on++
		}
	}
	if on == 0 {
		p = append(p, "a technique")
	}
	return p
}

// toDoc writes the form back into the document.
func (f *scopeForm) toDoc() map[string]any {
	d := cloneDoc(f.doc)
	d["schema_version"] = "1"
	d["id"] = slug(f.name)
	auth := map[string]any{"type": f.auth}
	if f.auth == "written" {
		auth["reference"] = strings.TrimSpace(f.ref)
	}
	d["authorization"] = auth
	d["valid"] = map[string]any{
		"not_before": f.today.Format("2006-01-02"),
		"not_after":  f.today.AddDate(0, 0, f.days).Format("2006-01-02"),
	}
	targets, _ := d["targets"].([]any)
	hosts := make([]any, len(f.targets))
	for i, h := range f.targets {
		hosts[i] = h
	}
	placed := false
	for _, t := range targets {
		if tm, ok := t.(map[string]any); ok && tm["hosts"] != nil {
			tm["hosts"] = hosts
			placed = true
			break
		}
	}
	if !placed {
		targets = append([]any{map[string]any{"name": "target", "hosts": hosts}}, targets...)
	}
	d["targets"] = targets
	net, _ := d["network"].(map[string]any)
	if net == nil {
		net = map[string]any{}
	}
	net["mode"] = map[string]string{"strict": "strict", "standard": "additive"}[f.net]
	deny := make([]any, len(f.out))
	for i, h := range f.out {
		deny[i] = h
	}
	net["deny"] = deny
	if net["allow"] == nil {
		net["allow"] = []any{}
	}
	d["network"] = net
	var allowed, forbidden, risky []any
	for _, t := range f.techs {
		if t.on {
			allowed = append(allowed, t.name)
		} else {
			forbidden = append(forbidden, t.name)
		}
	}
	for _, t := range f.risky {
		if t.on {
			allowed = append(allowed, t.name)
			risky = append(risky, t.name)
		} else {
			forbidden = append(forbidden, t.name)
		}
	}
	tech := map[string]any{"allowed": allowed, "forbidden": forbidden}
	if len(risky) > 0 {
		tech["risky"] = risky
	}
	d["techniques"] = tech
	return d
}

type scopeSavedMsg struct {
	res    ScopeResult
	err    error
	export bool
}

// ScopeSave (engine): `lab scope save --json` with the document on stdin.
func (e realEngine) ScopeSave(ctx context.Context, doc map[string]any, out string, force bool) (ScopeResult, error) {
	b, err := json.Marshal(doc)
	if err != nil {
		return ScopeResult{}, err
	}
	args := []string{"scope", "save", "--json"}
	if out != "" {
		args = append(args, "--out="+out)
	}
	if force {
		args = append(args, "--force")
	}
	var buf bytes.Buffer
	_, runErr := engine.ExecStreams(ctx, e.root, args, bytes.NewReader(b), &buf, io.Discard)
	var r ScopeResult
	if jerr := json.Unmarshal(buf.Bytes(), &r); jerr != nil {
		if runErr != nil {
			return r, runErr
		}
		return r, jerr
	}
	return r, nil
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

func (m model) saveScope(export bool, out string) tea.Cmd {
	f := m.form
	doc := f.toDoc()
	force := false
	if !export && f.path != "" {
		out, force = f.path, true
	}
	ctx, eng := m.ctx, m.eng
	return func() tea.Msg {
		r, err := eng.ScopeSave(ctx, doc, out, force)
		return scopeSavedMsg{res: r, err: err, export: export}
	}
}

func (m model) updateScopeForm(msg tea.Msg) (tea.Model, tea.Cmd) {
	f := m.form
	switch msg := msg.(type) {
	case scopeSavedMsg:
		f.busy = false
		if msg.err != nil && msg.res.Path == "" {
			f.errs = []string{sanitize.Line(msg.err.Error(), 300)}
			return m, nil
		}
		if msg.res.Error != "" {
			f.errs = []string{sanitize.Line(msg.res.Error, 300)}
			return m, nil
		}
		if !msg.res.Written {
			f.errs = nil
			for _, e := range msg.res.Errors {
				f.errs = append(f.errs, sanitize.Line(e, 300))
			}
			return m, nil
		}
		if msg.export {
			f.note = "exported to " + tildify(msg.res.Path)
			return m, nil
		}
		if !msg.res.Valid {
			f.errs = msg.res.Errors
			f.note = "saved to " + tildify(msg.res.Path) + "; fix what is listed before using it"
			return m, nil
		}
		return m.scopeDone(msg.res.Path)
	case tea.KeyMsg:
		return m.keyScopeForm(msg)
	}
	return m, nil
}

// scopeDone returns to the flow with the saved scope as the answer (or
// quits in `burner scope edit`).
func (m model) scopeDone(path string) (tea.Model, tea.Cmd) {
	if m.flow == nil {
		m.out.Code, m.out.Report = 0, path
		m.out.Action = "scope-saved"
		return m, tea.Quit
	}
	m.scr = scrFlow
	m.flow.record(path, path)
	return m.afterAnswer()
}

func (m model) keyScopeForm(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	f := m.form
	key := k.String()
	if f.adding != "" {
		switch key {
		case "esc":
			f.adding = ""
			f.input.Blur()
		case "enter":
			v := strings.TrimSpace(f.input.Value())
			f.input.SetValue("")
			what := f.adding
			f.adding = ""
			f.input.Blur()
			if v == "" {
				return m, nil
			}
			switch what {
			case "targets":
				f.targets = appendUniq(f.targets, sanitize.Line(v, 200))
			case "out":
				f.out = appendUniq(f.out, sanitize.Line(v, 200))
			case "export":
				f.busy = true
				return m, m.saveScope(true, expandHome(v))
			}
		default:
			var cmd tea.Cmd
			f.input, cmd = f.input.Update(k)
			return m, cmd
		}
		return m, nil
	}
	field := formFields[f.field]
	switch key {
	case "tab", "down":
		if key == "down" && field == "techs" && f.tcur < len(f.techs)+len(f.risky)-1 {
			f.tcur++
			return m, nil
		}
		f.field = (f.field + 1) % len(formFields)
		return m, nil
	case "shift+tab", "up":
		if key == "up" && field == "techs" && f.tcur > 0 {
			f.tcur--
			return m, nil
		}
		f.field = (f.field + len(formFields) - 1) % len(formFields)
		return m, nil
	case "esc":
		if m.flow == nil {
			m.out.Code = 130
			return m, tea.Quit
		}
		m.scr = scrFlow
		m.flow.back()
		return m, m.flow.focusCmd()
	case "enter":
		if len(f.problems()) > 0 || f.busy {
			return m, nil
		}
		f.busy, f.errs, f.note = true, nil, ""
		return m, m.saveScope(false, "")
	case "x":
		if field != "name" && !(field == "auth" && f.auth == "written") {
			f.adding = "export"
			f.input.Placeholder = "~/Documents/" + slug(f.name) + ".yaml"
			f.input.SetValue("~/Documents/" + slug(f.name) + ".yaml")
			return m, f.input.Focus()
		}
	}
	switch field {
	case "name":
		switch k.Type {
		case tea.KeyBackspace:
			if r := []rune(f.name); len(r) > 0 {
				f.name = string(r[:len(r)-1])
			}
		case tea.KeyRunes, tea.KeySpace:
			if len(f.name) < 63 {
				f.name += string(k.Runes)
			}
		}
	case "targets", "out":
		switch key {
		case "a", "+":
			f.adding = field
			f.input.Placeholder = "host or host:port"
			return m, f.input.Focus()
		case "backspace", "d":
			if field == "targets" && len(f.targets) > 0 {
				f.targets = f.targets[:len(f.targets)-1]
			} else if field == "out" && len(f.out) > 0 {
				f.out = f.out[:len(f.out)-1]
			}
		}
	case "auth":
		switch {
		case key == "left" || key == "right" || (key == " " && f.auth == "own-lab"):
			f.auth = map[string]string{"own-lab": "written", "written": "own-lab"}[f.auth]
		case f.auth == "written" && k.Type == tea.KeyBackspace:
			if r := []rune(f.ref); len(r) > 0 {
				f.ref = string(r[:len(r)-1])
			}
		case f.auth == "written" && (k.Type == tea.KeyRunes || k.Type == tea.KeySpace):
			if len(f.ref) < 300 {
				f.ref += string(k.Runes)
			}
		}
	case "days":
		opts := []int{7, 30, 90}
		i := 1
		for j, d := range opts {
			if d == f.days {
				i = j
			}
		}
		if key == "right" && i < 2 {
			i++
		}
		if key == "left" && i > 0 {
			i--
		}
		f.days = opts[i]
	case "techs":
		if key == " " {
			if f.tcur < len(f.techs) {
				f.techs[f.tcur].on = !f.techs[f.tcur].on
			} else if j := f.tcur - len(f.techs); j < len(f.risky) {
				f.risky[j].on = !f.risky[j].on
			}
		}
	case "net":
		if key == "left" || key == "right" || key == " " {
			f.net = map[string]string{"strict": "standard", "standard": "strict"}[f.net]
		}
	}
	return m, nil
}

func (m model) viewScopeForm() string {
	f := m.form
	w := m.w
	var b strings.Builder
	state := sRed.Render("needs " + strings.Join(f.problems(), ", "))
	if len(f.problems()) == 0 {
		state = sSoft.Render("valid")
	}
	left := sBold.Render("Scope") + sDim.Render(" · "+f.title) + "  " + state
	right := ""
	if m.flow != nil {
		right = trail(m.flow.sections(), "scope")
	}
	b.WriteString(header(w, left, right) + "\n")

	sideW := 40
	formW := w - sideW
	label := func(name, text string) string {
		if formFields[f.field] == name {
			return sAmber.Render("❯ " + text)
		}
		return sDim.Render("  " + text)
	}
	chip := func(s string, on bool) string {
		if on {
			return sSel.Render(" " + s + " ")
		}
		return sDim.Render(" " + s + " ")
	}
	var L []string
	cursor := func(name string) string {
		if formFields[f.field] == name {
			return sAmber.Render("▌")
		}
		return ""
	}
	L = append(L, label("name", "Name"), "    "+sText.Render(f.name)+cursor("name"), "")
	tl := "    "
	for _, t := range f.targets {
		tl += chip(t, true) + " "
	}
	L = append(L, label("targets", "Targets"), tl+sDim.Render("+ add host"))
	if f.adding == "targets" {
		L = append(L, "    "+f.input.View())
	}
	L = append(L, "", label("auth", "Authorization"), "    "+chip("own-lab", f.auth == "own-lab")+" "+chip("written", f.auth == "written"))
	if f.auth == "written" {
		ref := sText.Render(f.ref)
		if f.ref == "" {
			ref = sFaint.Render("contract, ticket or program URL")
		}
		L = append(L, "    "+sDim.Render("reference ")+ref+cursor("auth"))
	}
	dates := sDim.Render(f.today.Format("2006-01-02") + " → " + f.today.AddDate(0, 0, f.days).Format("2006-01-02"))
	L = append(L, "", label("days", "Valid for"), "    "+chip("7 days", f.days == 7)+" "+chip("30 days", f.days == 30)+" "+chip("90 days", f.days == 90)+"  "+dates)
	L = append(L, "", label("techs", "Techniques"))
	colW := max(20, (formW-8)/2)
	row := func(t techRow, i int, risky bool) string {
		box := sFaint.Render("[ ]")
		if t.on {
			box = sSoft.Render("[x]")
			if risky {
				box = sAmber.Render("[x]")
			}
		}
		s := box + " " + t.name
		if formFields[f.field] == "techs" && f.tcur == i {
			s = sSel.Render(box + " " + t.name)
		}
		return s + strings.Repeat(" ", max(1, colW-lipgloss.Width(box+" "+t.name)))
	}
	grid := func(rows []techRow, offset int, risky bool) {
		for i := 0; i < len(rows); i += 2 {
			line := "    " + row(rows[i], offset+i, risky)
			if i+1 < len(rows) {
				line += row(rows[i+1], offset+i+1, risky)
			}
			L = append(L, line)
		}
	}
	grid(f.techs, 0, false)
	L = append(L, "    "+sDim.Render("risky"))
	grid(f.risky, len(f.techs), true)
	ol := "    "
	for _, t := range f.out {
		ol += chip(t, false) + " "
	}
	L = append(L, "", label("out", "Out of scope"), ol+sDim.Render("+ add host"))
	if f.adding == "out" {
		L = append(L, "    "+f.input.View())
	}
	L = append(L, "", label("net", "Network"), "    "+chip("strict", f.net == "strict")+" "+chip("standard", f.net == "standard"))
	if f.adding == "export" {
		L = append(L, "", sBold.Render("Export to"), "    "+f.input.View())
	}
	for _, e := range f.errs {
		for _, t := range wrap(e, formW-8) {
			L = append(L, "  "+sAmber.Render(t))
		}
	}
	if f.note != "" {
		L = append(L, "", "  "+sSoft.Render(f.note))
	}

	// Preview.
	on, risky := 0, 0
	for _, t := range f.techs {
		if t.on {
			on++
		}
	}
	for _, t := range f.risky {
		if t.on {
			on++
			risky++
		}
	}
	auth := f.auth
	if f.auth == "written" {
		if f.ref == "" {
			auth += " · " + sRed.Render("missing ref")
		} else {
			auth += " · " + f.ref
		}
	}
	tech := fmt.Sprintf("%d on", on)
	if risky > 0 {
		tech += " · " + sAmber.Render(fmt.Sprintf("%d risky", risky))
	}
	outN := "-"
	if len(f.out) > 0 {
		outN = fmt.Sprint(len(f.out))
	}
	kv := func(k, v string) string { return sDim.Render(fmt.Sprintf("%-14s", k)) + sSoft.Render(v) }
	P := []string{sDim.Render("PREVIEW"),
		kv("authorization", auth),
		kv("targets", strings.Join(f.targets, ", ")),
		kv("valid", fmt.Sprintf("%d days", f.days)),
		kv("network", f.net),
		kv("techniques", tech),
		kv("out of scope", outN),
		kv("owner", f.owner),
		"", sDim.Render("SAVE")}
	if f.path != "" {
		P = append(P, sSoft.Render(tildify(f.path)))
	} else {
		P = append(P, sSoft.Render("~/.burner/scopes/")+sDim.Render(slug(f.name)+".yaml"))
	}
	P = append(P, sSoft.Render("export to…")+strings.Repeat(" ", max(1, sideW-16))+sDim.Render("x"))
	if f.busy {
		P = append(P, "", sAmber.Render(m.spin())+" "+sDim.Render("saving"))
	}
	for i := range P {
		P[i] = ellipsis(P[i], sideW-4)
	}

	bodyH := m.h - 2
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
		col(formW, bodyH, strings.Join(L, "\n"), "left"),
		col(sideW, bodyH, strings.Join(P, "\n"), "right")) + "\n")
	keys := []string{"tab", "next field", "space", "toggle", "←→", "choose", "a", "add host", "enter", "save + use", "x", "export", "esc", "back"}
	if m.flow == nil {
		keys[9] = "save"
	}
	b.WriteString(hints(keys...))
	return b.String()
}

// RunScopeEdit opens the scope form on an existing file (`burner scope
// edit FILE`); saving replaces the file.
func RunScopeEdit(ctx context.Context, cfg Config, path string) (Outcome, error) {
	setupColor()
	m := initialModel(ctx, cfg)
	r, err := m.eng.ScopeCheck(ctx, path)
	if err != nil && r.Scope == nil {
		return Outcome{Code: 2}, err
	}
	if len(r.Scope) == 0 {
		why := "not a scope file"
		if len(r.Errors) > 0 {
			why = sanitize.Line(r.Errors[0], 300)
		}
		return Outcome{Code: 2}, fmt.Errorf("%s: %s", path, why)
	}
	m.form = newScopeForm(r.Scope, filepath.Base(path), path, m.cfg.Now())
	m.scr = scrScopeForm
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithContext(ctx))
	final, err := p.Run()
	if err != nil {
		return Outcome{Code: 1}, err
	}
	fm, _ := final.(model)
	return fm.out, nil
}
