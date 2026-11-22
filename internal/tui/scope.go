package tui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/BRYANN2K/sbx-burner/internal/catalog"
	"github.com/BRYANN2K/sbx-burner/internal/engine"
	"github.com/BRYANN2K/sbx-burner/internal/sanitize"
)

// ScopeResult is what `lab scope new --json` and `lab scope FILE --json`
// print.
type ScopeResult struct {
	Path    string         `json:"path"`
	Written bool           `json:"written"`
	Valid   bool           `json:"valid"`
	Errors  []string       `json:"errors"`
	Todo    []string       `json:"todo"`
	Notes   []string       `json:"notes"`
	Summary ScopeSummary   `json:"summary"`
	Scope   map[string]any `json:"scope"`
	Error   string         `json:"error"`
}

// ScopeSummary is the one-line view of a scope to create.
type ScopeSummary struct {
	Hosts []string `json:"hosts"`
	Auth  string   `json:"auth"`
	Days  int      `json:"days"`
}

// scopeArgs are the target flags `scope new` takes from the run options.
func scopeArgs(o engine.RunOptions) []string {
	var a []string
	add := func(flag, v string) {
		if v != "" {
			a = append(a, flag+"="+v)
		}
	}
	add("--target-url", o.TargetURL)
	add("--target-port", o.TargetPort)
	add("--app-port", o.AppPort)
	return a
}

// scopeKey identifies the target a scope was made for.
func scopeKey(o engine.RunOptions) string {
	return strings.Join(append([]string{o.Recipe}, scopeArgs(o)...), "\x00")
}

func engineJSON(ctx context.Context, root string, v any, args ...string) error {
	var out bytes.Buffer
	_, err := engine.ExecStreams(ctx, root, args, nil, &out, io.Discard)
	if out.Len() > 1<<20 {
		return fmt.Errorf("engine output too large")
	}
	if jerr := json.Unmarshal(out.Bytes(), v); jerr != nil {
		if err != nil {
			return err
		}
		return jerr
	}
	return nil
}

func (e realEngine) ScopeNew(ctx context.Context, o engine.RunOptions, reference string, dryRun bool) (ScopeResult, error) {
	args := append([]string{"scope", "new", o.Recipe}, scopeArgs(o)...)
	if reference != "" {
		args = append(args, "--reference="+reference)
	}
	if dryRun {
		args = append(args, "--dry-run")
	}
	var r ScopeResult
	err := engineJSON(ctx, e.root, &r, append(args, "--json")...)
	return r, err
}

func (e realEngine) ScopeCheck(ctx context.Context, path string) (ScopeResult, error) {
	var r ScopeResult
	err := engineJSON(ctx, e.root, &r, "scope", path, "--json")
	return r, err
}

// savedScopes lists ~/.burner/scopes/<recipe>-*.yaml, newest first.
func savedScopes(r catalog.Recipe) []string {
	dir := filepath.Join(catalog.Home(), "scopes")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	type f struct {
		path string
		mod  int64
	}
	var fs []f
	for _, e := range entries {
		n := e.Name()
		if !e.Type().IsRegular() || !strings.HasPrefix(n, r.Name+"-") || !strings.HasSuffix(n, ".yaml") {
			continue
		}
		if info, err := e.Info(); err == nil {
			fs = append(fs, f{filepath.Join(dir, n), info.ModTime().UnixNano()})
		}
	}
	sort.Slice(fs, func(i, j int) bool { return fs[i].mod > fs[j].mod })
	out := make([]string, len(fs))
	for i, x := range fs {
		out[i] = x.path
	}
	return out
}

func summaryLine(s ScopeSummary) string {
	hosts := strings.Join(s.Hosts, ", ")
	if hosts == "" {
		hosts = "no hosts"
	}
	return fmt.Sprintf("%s · %s · %d days", hosts, s.Auth, s.Days)
}

type scopeMsg struct {
	key  string
	kind string // dry | create | check
	res  ScopeResult
	err  error
}

type editedMsg struct {
	path string
	err  error
}

// startLoad runs what a loading question waits for.
func (m model) startLoad() tea.Cmd {
	f := m.flow
	if f.q == nil {
		return nil
	}
	switch f.q.loader {
	case "models":
		return m.loadModels()
	case "scope-dry", "scope-create":
		key := f.q.loadKey
		if f.inflight[key] {
			return nil
		}
		f.inflight[key] = true
		ctx, eng, o, ref, dry := m.ctx, m.eng, f.q.loadOpts, f.q.loadRef, f.q.loader == "scope-dry"
		kind := "create"
		if dry {
			kind = "dry"
		}
		return func() tea.Msg {
			r, err := eng.ScopeNew(ctx, o, ref, dry)
			return scopeMsg{key: key, kind: kind, res: r, err: err}
		}
	}
	return nil
}

func (m model) checkScope(path, key string) tea.Cmd {
	ctx, eng := m.ctx, m.eng
	return func() tea.Msg {
		r, err := eng.ScopeCheck(ctx, path)
		return scopeMsg{key: key, kind: "check", res: r, err: err}
	}
}

// editScope opens the scope in $VISUAL / $EDITOR (vi by default).
func editScope(path string) tea.Cmd {
	ed := os.Getenv("VISUAL")
	if ed == "" {
		ed = os.Getenv("EDITOR")
	}
	if ed == "" {
		ed = "vi"
	}
	parts := strings.Fields(ed)
	cmd := exec.Command(parts[0], append(parts[1:], path)...)
	return tea.ExecProcess(cmd, func(err error) tea.Msg { return editedMsg{path: path, err: err} })
}

// previewLines renders the scope to create or reuse: authorization,
// targets, valid, network, techniques, then what is left to fix.
func previewLines(r ScopeResult, w int) []string {
	s := r.Scope
	str := func(v any) string { return sanitize.Line(fmt.Sprint(v), 300) }
	list := func(v any) string {
		xs, _ := v.([]any)
		var out []string
		for _, x := range xs {
			out = append(out, str(x))
		}
		if len(out) == 0 {
			return "none"
		}
		return strings.Join(out, ", ")
	}
	get := func(m any, k string) any {
		mm, _ := m.(map[string]any)
		return mm[k]
	}
	kv := func(k, v string) []string {
		var out []string
		for i, l := range wrap(v, max(10, w-14)) {
			key := ""
			if i == 0 {
				key = k
			}
			out = append(out, sDim.Render(fmt.Sprintf("%-14s", key))+sText.Render(l))
		}
		return out
	}
	var lines []string
	auth := str(get(s["authorization"], "type"))
	if ref := get(s["authorization"], "reference"); ref != nil {
		auth += " · " + str(ref)
	}
	lines = append(lines, kv("authorization", auth)...)
	if o := s["owner"]; o != nil {
		lines = append(lines, kv("owner", str(o)+" · owner is not an authorization")...)
	}
	targets, _ := s["targets"].([]any)
	for i, t := range targets {
		label := ""
		if i == 0 {
			label = "targets"
		}
		v := str(get(t, "name"))
		if h := get(t, "hosts"); h != nil {
			v += ": " + list(h)
		}
		if p := get(t, "paths"); p != nil {
			v += ": " + list(p)
		}
		lines = append(lines, kv(label, v)...)
	}
	lines = append(lines, kv("valid", str(get(s["valid"], "not_before"))+" to "+str(get(s["valid"], "not_after")))...)
	lines = append(lines, kv("network", str(get(s["network"], "mode"))+" · allow "+list(get(s["network"], "allow"))+" · deny "+list(get(s["network"], "deny")))...)
	lines = append(lines, kv("techniques", list(get(s["techniques"], "allowed")))...)
	lines = append(lines, kv("forbidden", list(get(s["techniques"], "forbidden")))...)
	lines = append(lines, kv("file", tildify(r.Path))...)
	for _, n := range r.Notes {
		lines = append(lines, "", sDim.Render(sanitize.Line(n, 300)))
	}
	if len(r.Errors) > 0 {
		lines = append(lines, "")
		for _, e := range r.Errors {
			for _, l := range wrap("to fix: "+sanitize.Line(e, 500), w) {
				lines = append(lines, sAmber.Render(l))
			}
		}
	}
	return lines
}
