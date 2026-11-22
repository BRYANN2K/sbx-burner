package tui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/BRYANN2K/sbx-burner/internal/catalog"
	"github.com/BRYANN2K/sbx-burner/internal/engine"
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

// startLoad runs what a loading question waits for.
func (m model) startLoad() tea.Cmd {
	f := m.flow
	if f.q == nil {
		return nil
	}
	switch f.q.loader {
	case "models":
		return m.loadModels()
	case "scope-dry":
		key := f.q.loadKey
		if f.inflight[key] {
			return nil
		}
		f.inflight[key] = true
		ctx, eng, o := m.ctx, m.eng, f.q.loadOpts
		return func() tea.Msg {
			r, err := eng.ScopeNew(ctx, o, "", true)
			return scopeMsg{key: key, kind: "dry", res: r, err: err}
		}
	}
	return nil
}
