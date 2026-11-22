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
	"github.com/charmbracelet/x/ansi"

	"github.com/BRYANN2K/sbx-burner/internal/engine"
	"github.com/BRYANN2K/sbx-burner/internal/sanitize"
)

// Risky techniques, off by default (lab/scope.py RISKY); checking one
// writes it under techniques.risky.
var riskyTechs = []string{"brute-force", "lockout-testing", "credential-reuse", "dos", "ddos", "data-destruction", "social-engineering", "phishing", "physical", "ransomware"}

// techDesc is the one line shown next to the focused technique.
var techDesc = map[string]string{
	"recon":                      "passive discovery: DNS, headers, public pages",
	"scan":                       "port and service scans of the targets",
	"automated-scanning":         "scanners such as nuclei, ZAP or nikto",
	"endpoint-mapping":           "list routes, parameters and APIs",
	"content-discovery":          "find hidden paths and files with a wordlist",
	"passive-scan":               "observe traffic and responses, send no attacks",
	"rate-limit-observation":     "watch how the target throttles requests",
	"authz-testing":              "what each role is allowed to do",
	"input-validation":           "malformed and boundary inputs",
	"code-review":                "read the source for flaws",
	"local-dynamic-confirmation": "confirm a finding by running the code locally",
	"remote-testing":             "send requests to the deployed target",
	"auth-testing":               "login, password reset and MFA flows",
	"session-testing":            "cookies, tokens and session lifetime",
	"access-control-testing":     "one user reaching another user's data",
	"input-validation-testing":   "malformed and boundary inputs",
	"injection-testing":          "SQL, command and template injection",
	"business-logic-testing":     "abuse of the app's own workflows",
	"exploit":                    "prove a finding with a working exploit",
	"exploit-weaponization":      "turn a proof into a reusable attack",
	"static-analysis":            "read code or binaries without running them",
	"dynamic-analysis":           "run the sample and watch what it does",
	"disassembly":                "disassemble or decompile binaries",
	"debugger":                   "step through the program in a debugger",
	"file-handling":              "open, unpack and parse the files",
	"input-crafting":             "craft inputs that trigger a behaviour",
	"network-access":             "let the sample reach the network",
	"oob-callback":               "out-of-band callbacks to a host you control",
	"pivot":                      "use one target to reach another",
	"brute-force":                "guess passwords or keys at volume",
	"lockout-testing":            "trigger account lockouts",
	"credential-reuse":           "try found credentials on other services",
	"dos":                        "degrade or stop a service",
	"ddos":                       "distributed denial of service",
	"data-destruction":           "delete or corrupt data",
	"social-engineering":         "manipulate people into acting",
	"phishing":                   "deceptive messages to people",
	"physical":                   "physical access to sites or devices",
	"ransomware":                 "encrypt data the way ransomware does",
}

var formFields = []string{"name", "targets", "auth", "days", "techs", "out", "net"}

type techRow struct {
	name string
	on   bool
}

// scopeForm is the scope form: it edits a scope document and keeps every
// field it does not show (notes, test accounts, extra targets).
type scopeForm struct {
	overwrite bool // the file exists: the next enter replaces it
	doc       map[string]any
	path      string // scope edit: the file to replace
	title     string // category/recipe, or the file name
	field     int
	name      string
	targets   []string
	auth      string
	ref       string
	days      int
	techs     []techRow
	risky     []techRow
	tcur      int // cursor in techs then risky
	out       []string
	net       string // strict | standard
	owner     string
	adding    string // "targets" | "out" | "export"
	input     textinput.Model
	busy      bool
	errs      []string
	note      string
	today     time.Time
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
	if !export && f.overwrite {
		force = true
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
				if strings.HasSuffix(e, " exists") && !msg.export {
					f.overwrite = true
					continue
				}
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
		if formFields[f.field] == "techs" {
			f.tcur = 0 // entering from above: the first row
		}
		return m, nil
	case "shift+tab", "up":
		if key == "up" && field == "techs" && f.tcur > 0 {
			f.tcur--
			return m, nil
		}
		f.field = (f.field + len(formFields) - 1) % len(formFields)
		if formFields[f.field] == "techs" {
			f.tcur = len(f.techs) + len(f.risky) - 1 // entering from below: the last row
		}
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
		cmd := m.saveScope(false, "")
		f.overwrite = false
		return m, cmd
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
		if key == "a" || key == "n" {
			for i := range f.techs {
				f.techs[i].on = key == "a"
			}
		}
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
	inner := formW - 4 // inside the column border and padding
	focus := func(name string) bool { return formFields[f.field] == name }
	label := func(name, text string) string {
		if focus(name) {
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
	// value is a field's value line: highlighted full width when the field
	// has focus (plain text, the choice in brackets), styled otherwise.
	value := func(name, styled, plain string) string {
		if focus(name) {
			return "  " + sel(inner-2, "  "+plain)
		}
		return "    " + styled
	}
	choices := func(opts []string, cur string) (string, string) {
		var st, pl []string
		for _, o := range opts {
			st = append(st, chip(o, o == cur))
			if o == cur {
				pl = append(pl, "["+o+"]")
			} else {
				pl = append(pl, " "+o+" ")
			}
		}
		return strings.Join(st, " "), strings.Join(pl, " ")
	}
	hosts := func(hs []string, on bool) (string, string) {
		styled, plain := "", ""
		for _, h := range hs {
			styled += chip(h, on) + " "
			plain += h + "  "
		}
		return styled + sDim.Render("+ add host"), plain + "+ add host"
	}
	caret := ""
	if focus("name") || focus("auth") {
		caret = "▌"
	}
	var L []string
	L = append(L, label("name", "Name"), value("name", sText.Render(f.name), f.name+caret), "")
	st, pl := hosts(f.targets, true)
	L = append(L, label("targets", "Targets"), value("targets", st, pl))
	if f.adding == "targets" {
		L = append(L, "    "+f.input.View())
	}
	st, pl = choices([]string{"own-lab", "written"}, f.auth)
	L = append(L, "", label("auth", "Authorization"), value("auth", st, pl))
	if f.auth == "written" {
		ref := sText.Render(f.ref)
		if f.ref == "" {
			ref = sFaint.Render("contract, ticket or program URL")
		}
		L = append(L, value("auth", sDim.Render("reference ")+ref, "reference "+f.ref+caret))
	}
	dates := f.today.Format("2006-01-02") + " → " + f.today.AddDate(0, 0, f.days).Format("2006-01-02")
	st, pl = choices([]string{"7 days", "30 days", "90 days"}, fmt.Sprintf("%d days", f.days))
	L = append(L, "", label("days", "Valid for"), value("days", st+"  "+sDim.Render(dates), pl+"  "+dates))
	L = append(L, "", label("techs", "Techniques"))
	row := func(t techRow, i int, risky bool) string {
		mark := "[ ]"
		if t.on {
			mark = "[x]"
		}
		if focus("techs") && f.tcur == i {
			line := "❯ " + mark + " " + t.name
			if d := techDesc[t.name]; d != "" {
				line = ellipsis(line+strings.Repeat(" ", max(2, 30-lipgloss.Width(line)))+d, inner-2)
			}
			return "  " + sel(inner-2, line)
		}
		switch {
		case t.on && risky:
			return "      " + sAmber.Render(mark+" "+t.name)
		case t.on:
			return "      " + sSoft.Render(mark) + " " + sText.Render(t.name)
		}
		return "      " + sFaint.Render(mark) + " " + sDim.Render(t.name)
	}
	for i, t := range f.techs {
		L = append(L, row(t, i, false))
	}
	L = append(L, "", "    "+sDim.Render("risky"))
	for i, t := range f.risky {
		L = append(L, row(t, len(f.techs)+i, true))
	}
	st, pl = hosts(f.out, false)
	L = append(L, "", label("out", "Out of scope"), value("out", st, pl))
	if f.adding == "out" {
		L = append(L, "    "+f.input.View())
	}
	st, pl = choices([]string{"strict", "standard"}, f.net)
	L = append(L, "", label("net", "Network"), value("net", st, pl))
	if f.adding == "export" {
		L = append(L, "", sBold.Render("Export to"), "    "+f.input.View())
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
	// Problems, errors and notes live here, always visible, not at the
	// bottom of a form that may be scrolled.
	if pr := f.problems(); len(pr) > 0 {
		P = append(P, "", sAmber.Render("needs "+strings.Join(pr, ", ")))
	}
	for _, e := range f.errs {
		for _, t := range wrap(e, sideW-4) {
			P = append(P, sAmber.Render(t))
		}
	}
	if f.overwrite {
		P = append(P, "", sAmber.Render("this scope exists"), sSoft.Render("enter again to replace it"))
	}
	if f.note != "" {
		for _, t := range wrap(f.note, sideW-4) {
			P = append(P, sSoft.Render(t))
		}
	}
	for i := range P {
		P[i] = ellipsis(P[i], sideW-4)
	}

	bodyH := m.h - 2
	// A long form scrolls to keep the focused line (the last "❯ ") in view.
	if avail := bodyH - 2; avail > 0 && len(L) > avail {
		at := 0
		for i, l := range L {
			if strings.Contains(ansi.Strip(l), "❯ ") {
				at = i
			}
		}
		start := min(max(0, at-avail/2), len(L)-avail)
		L = L[start : start+avail]
	}
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
		col(formW, bodyH, strings.Join(L, "\n"), "left"),
		col(sideW, bodyH, strings.Join(P, "\n"), "right")) + "\n")
	save := "save + use"
	if m.flow == nil {
		save = "save"
	}
	keys := []string{"↑↓", "move", "tab", "next field"}
	switch formFields[f.field] {
	case "techs":
		keys = append(keys, "space", "toggle", "a", "all", "n", "none")
	case "targets", "out":
		keys = append(keys, "a", "add host", "d", "remove last")
	case "auth", "days", "net":
		keys = append(keys, "←→", "choose")
	}
	keys = append(keys, "enter", save, "x", "export", "esc", "back")
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
