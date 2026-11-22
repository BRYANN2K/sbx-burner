// Package mcp is `burner mcp`: a stdio MCP server that lets an agent list
// recipes and run them, inside limits the host user sets.
//
// Trust model (same rule as macsbx ADR 0005): the server runs on the host
// with the user's permissions, so a client can never widen its own access.
//   - Scopes are files the user wrote in scopes_dir; a client picks one by
//     name and can never write, edit or pass its own scope.
//   - Path targets must resolve (symlinks included) under target_roots.
//   - Image and URL targets can be turned off; URLs still need a scope.
//   - No tool runs a shell or reads arbitrary host files; reports are read
//     only from runs this client started.
//   - Ownership comes from $BURNER_CLIENT or a random per-process token,
//     never from the client's self-reported name.
package mcp

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/BRYANN2K/sbx-burner/internal/catalog"
	"github.com/BRYANN2K/sbx-burner/internal/engine"
	"github.com/BRYANN2K/sbx-burner/internal/events"
)

const protocolVersion = "2025-06-18"

// Config is ~/.burner/mcp.yaml. Only the host user edits it.
type Config struct {
	TargetRoots []string `yaml:"target_roots"`
	ScopesDir   string   `yaml:"scopes_dir"`
	AllowImages bool     `yaml:"allow_images"`
	AllowURLs   bool     `yaml:"allow_urls"`
	AllowRepos  []string `yaml:"allow_repos"` // GitHub owners (or owner/repo) a client may clone
	MaxRunning  int      `yaml:"max_running"`
}

// LoadConfig reads the config; a missing file means the strictest defaults:
// no target roots, no images, no URLs, one run at a time.
func LoadConfig(home string) (Config, error) {
	cfg := Config{ScopesDir: filepath.Join(home, "scopes"), MaxRunning: 1}
	raw, err := os.ReadFile(filepath.Join(home, "mcp.yaml"))
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("mcp.yaml: %w", err)
	}
	for i, r := range cfg.TargetRoots {
		cfg.TargetRoots[i] = expandHome(r)
	}
	cfg.ScopesDir = expandHome(cfg.ScopesDir)
	if cfg.MaxRunning <= 0 {
		cfg.MaxRunning = 1
	}
	return cfg, nil
}

// Server is one MCP session over stdio.
type Server struct {
	Root    string // catalog root
	Home    string // ~/.burner
	Config  Config
	Client  string // ownership token
	Version string

	// Exec runs the engine; tests replace it.
	Exec func(ctx context.Context, root string, args []string, w io.Writer) (int, error)

	mu   sync.Mutex
	runs map[string]*runState
	out  *json.Encoder
	wmu  sync.Mutex
}

type runState struct {
	ID       string    `json:"run_id"`
	Recipe   string    `json:"recipe"`
	Owner    string    `json:"-"`
	Dir      string    `json:"-"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished,omitempty"`
	Status   string    `json:"status"` // running | done | failed
	ExitCode int       `json:"exit_code"`
}

// ClientToken returns $BURNER_CLIENT or a random token.
func ClientToken() string {
	if t := strings.TrimSpace(os.Getenv("BURNER_CLIENT")); t != "" {
		return t
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Serve reads newline-delimited JSON-RPC from in until EOF.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	if s.Exec == nil {
		s.Exec = engine.ExecTo
	}
	s.runs = map[string]*runState{}
	s.out = json.NewEncoder(out)
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			s.reply(json.RawMessage("null"), nil, &rpcError{-32700, "parse error"})
			continue
		}
		if len(req.ID) == 0 { // notification
			continue
		}
		if string(req.ID) == "null" {
			s.reply(req.ID, nil, &rpcError{-32600, "id must not be null"})
			continue
		}
		result, rerr := s.dispatch(ctx, req)
		s.reply(req.ID, result, rerr)
	}
	return sc.Err()
}

func (s *Server) reply(id json.RawMessage, result any, rerr *rpcError) {
	msg := map[string]any{"jsonrpc": "2.0", "id": id}
	if rerr != nil {
		msg["error"] = rerr
	} else {
		msg["result"] = result
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_ = s.out.Encode(msg)
}

func (s *Server) dispatch(ctx context.Context, req request) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		return map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "burner", "version": s.Version},
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": toolDefs()}, nil
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, &rpcError{-32602, "invalid params"}
		}
		out, err := s.call(ctx, p.Name, p.Arguments)
		if err != nil {
			return toolResult(map[string]any{"error": err.Error()}, true), nil
		}
		return toolResult(out, false), nil
	default:
		return nil, &rpcError{-32601, "method not found: " + req.Method}
	}
}

func toolResult(v any, isError bool) map[string]any {
	b, _ := json.Marshal(v)
	return map[string]any{
		"content":           []map[string]any{{"type": "text", "text": string(b)}},
		"structuredContent": v,
		"isError":           isError,
	}
}

func toolDefs() []map[string]any {
	str := map[string]any{"type": "string"}
	runProps := map[string]any{
		"recipe":       str,
		"scope":        map[string]any{"type": "string", "description": "name of a scope file in the host's scopes directory (list_scopes)"},
		"agent":        map[string]any{"type": "string", "description": "an agent the runner can launch (burner agents); the engine refuses unknown names"},
		"target":       map[string]any{"type": "string", "description": "host path under an allowed target root"},
		"target_image": str,
		"target_port":  str,
		"target_url":   str,
		"target_repo":  map[string]any{"type": "string", "description": "owner/repo[@ref]; owner must be in allow_repos"},
		"target_app":   map[string]any{"type": "string", "description": "project folder under a target root, or owner/repo[@ref]"},
		"app_cmd":      str,
		"app_port":     str,
		"prompt":       map[string]any{"type": "string", "description": "extra notes for the agent; cannot change the scope"},
		"demo":         map[string]any{"type": "boolean"},
	}
	obj := func(props map[string]any, required ...string) map[string]any {
		return map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}
	}
	return []map[string]any{
		{"name": "list_recipes", "description": "List runnable recipes with their accepted target kinds.", "inputSchema": obj(map[string]any{})},
		{"name": "describe_recipe", "description": "Show one recipe: summary, targets, scope need, risk.", "inputSchema": obj(map[string]any{"recipe": str}, "recipe")},
		{"name": "list_scopes", "description": "List scope files the host user prepared. Scopes cannot be created or edited here.", "inputSchema": obj(map[string]any{})},
		{"name": "plan_run", "description": "Dry run: return the exact plan without running anything.", "inputSchema": obj(runProps, "recipe")},
		{"name": "run", "description": "Start a run in the background. Returns run_id; poll run_status.", "inputSchema": obj(runProps, "recipe")},
		{"name": "run_status", "description": "Status of a run this client started.", "inputSchema": obj(map[string]any{"run_id": str}, "run_id")},
		{"name": "run_events", "description": "Live events of a run this client started, after a cursor (seq).", "inputSchema": obj(map[string]any{"run_id": str, "after": map[string]any{"type": "integer"}}, "run_id")},
		{"name": "answer", "description": "Answer a question the agent asked in a run this client started.", "inputSchema": obj(map[string]any{"run_id": str, "ask_id": str, "value": str}, "run_id", "ask_id", "value")},
		{"name": "get_report", "description": "report.json of a finished run this client started.", "inputSchema": obj(map[string]any{"run_id": str}, "run_id")},
	}
}

func (s *Server) call(ctx context.Context, name string, args map[string]any) (any, error) {
	switch name {
	case "list_recipes":
		recipes, _ := catalog.Load(s.Root)
		out := []map[string]any{}
		for _, r := range recipes {
			if r.Runnable() {
				out = append(out, map[string]any{"id": recipeRef(r), "summary": r.Summary, "targets": r.Targets, "scope": r.Scope, "risk": r.Risk})
			}
		}
		return map[string]any{"recipes": out}, nil
	case "describe_recipe":
		r, err := s.recipe(args)
		if err != nil {
			return nil, err
		}
		return r, nil
	case "list_scopes":
		return map[string]any{"scopes": s.scopes()}, nil
	case "plan_run", "run":
		r, err := s.recipe(args)
		if err != nil {
			return nil, err
		}
		opts, err := s.runOptions(r, args)
		if err != nil {
			return nil, err
		}
		if name == "plan_run" {
			opts.DryRun = true
			var buf strings.Builder
			code, err := s.Exec(ctx, s.Root, opts.Args(), &buf)
			if err != nil {
				return nil, err
			}
			return map[string]any{"exit_code": code, "plan": buf.String()}, nil
		}
		return s.start(r, opts)
	case "run_status":
		st, err := s.owned(args)
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		return *st, nil
	case "run_events":
		st, err := s.owned(args)
		if err != nil {
			return nil, err
		}
		after := -1
		if v, ok := args["after"].(float64); ok {
			after = int(v)
		}
		f, err := os.Open(filepath.Join(st.Dir, "events.ndjson"))
		if err != nil {
			return map[string]any{"events": []any{}}, nil
		}
		defer f.Close()
		list := []events.Event{}
		_ = events.Read(f, func(e events.Event) {
			if e.Seq > after && len(list) < 500 {
				list = append(list, e)
			}
		})
		return map[string]any{"events": list}, nil
	case "answer":
		st, err := s.owned(args)
		if err != nil {
			return nil, err
		}
		askID, _ := args["ask_id"].(string)
		value, _ := args["value"].(string)
		socks, _ := filepath.Glob(filepath.Join(st.Dir, "runs", "*", "control.sock"))
		if len(socks) != 1 {
			return nil, errors.New("the run has no open question channel")
		}
		if err := events.Answer(socks[0], askID, value); err != nil {
			return nil, err
		}
		return map[string]any{"delivered": true}, nil
	case "get_report":
		st, err := s.owned(args)
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		status, dir := st.Status, st.Dir
		s.mu.Unlock()
		if status == "running" {
			return nil, errors.New("run still in progress")
		}
		matches, _ := filepath.Glob(filepath.Join(dir, "runs", "*", "report.json"))
		if len(matches) == 0 {
			return nil, errors.New("no report: the run ended before writing one (see run_status)")
		}
		raw, err := os.ReadFile(matches[0])
		if err != nil {
			return nil, err
		}
		var report any
		if err := json.Unmarshal(raw, &report); err != nil {
			return nil, err
		}
		return report, nil
	}
	return nil, fmt.Errorf("unknown tool %q", name)
}

func (s *Server) recipe(args map[string]any) (catalog.Recipe, error) {
	ref, _ := args["recipe"].(string)
	recipes, _ := catalog.Load(s.Root)
	r, err := catalog.Find(recipes, strings.TrimPrefix(ref, "mine/"))
	if err != nil {
		return r, err
	}
	if !r.Runnable() {
		return r, fmt.Errorf("%s is not available yet", r.ID)
	}
	return r, nil
}

// runOptions turns tool arguments into engine flags, enforcing the limits.
func (s *Server) runOptions(r catalog.Recipe, args map[string]any) (engine.RunOptions, error) {
	o := engine.RunOptions{Recipe: r.EngineRef(), Agent: "claude"}
	get := func(k string) string { v, _ := args[k].(string); return strings.TrimSpace(v) }
	if a := get("agent"); a != "" {
		if !engine.ValidAgentName(a) {
			return o, fmt.Errorf("agent %q is not a valid agent name", a)
		}
		o.Agent = a
	}
	if name := get("scope"); name != "" {
		path, err := s.scopePath(name)
		if err != nil {
			return o, err
		}
		o.Scope = path
	}
	if t := get("target"); t != "" {
		path, err := s.allowedPath(t)
		if err != nil {
			return o, err
		}
		o.Target = path
	}
	if img := get("target_image"); img != "" {
		if !s.Config.AllowImages {
			return o, errors.New("image targets are turned off in ~/.burner/mcp.yaml (allow_images)")
		}
		if looksLikePath(img) || existsUnder(s.Root, img) {
			if !filepath.IsAbs(expandHome(img)) && !strings.HasPrefix(img, "~") {
				return o, errors.New("an image tarball must be given as an absolute path under a target root")
			}
			path, err := s.allowedPath(img) // tarballs follow the path rule
			if err != nil {
				return o, err
			}
			if st, err := os.Stat(path); err != nil || !st.Mode().IsRegular() {
				return o, errors.New("an image tarball must be a regular file")
			}
			img = path
		} else if !imageRef.MatchString(img) {
			return o, fmt.Errorf("invalid image reference %q", img)
		}
		o.TargetImage = img
		o.TargetPort = get("target_port")
	}
	if u := get("target_url"); u != "" {
		if !s.Config.AllowURLs {
			return o, errors.New("URL targets are turned off in ~/.burner/mcp.yaml (allow_urls)")
		}
		if o.Scope == "" {
			return o, errors.New("a URL target needs a scope (list_scopes)")
		}
		o.TargetURL = u
	}
	if repo := get("target_repo"); repo != "" {
		if err := s.allowedRepo(repo); err != nil {
			return o, err
		}
		o.TargetRepo = repo
	}
	if app := get("target_app"); app != "" {
		if looksLikeRepo(app) {
			if err := s.allowedRepo(app); err != nil {
				return o, err
			}
			o.TargetApp = app
		} else {
			path, err := s.allowedPath(app)
			if err != nil {
				return o, err
			}
			o.TargetApp = path
		}
		o.AppCmd, o.AppPort = get("app_cmd"), get("app_port")
	}
	if p := get("prompt"); p != "" {
		if len(p) > MaxPrompt {
			return o, fmt.Errorf("prompt longer than %d bytes", MaxPrompt)
		}
		o.Prompts = []string{p}
	}
	if d, _ := args["demo"].(bool); d {
		o.Demo = true
	}
	if r.Scope == "required" && o.Scope == "" {
		return o, errors.New(r.ID + " needs a scope (list_scopes)")
	}
	if r.TargetMode == "required" && !o.HasTarget() {
		return o, errors.New(r.ID + " needs a target: " + strings.Join(r.Targets, ", "))
	}
	return o, nil
}

func (s *Server) scopes() []string {
	entries, _ := os.ReadDir(s.Config.ScopesDir)
	out := []string{}
	for _, e := range entries {
		if !e.IsDir() && (strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml")) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// scopePath accepts only a bare file name listed in scopes_dir.
func (s *Server) scopePath(name string) (string, error) {
	if filepath.Base(name) != name || strings.HasPrefix(name, ".") {
		return "", errors.New("scope must be a name from list_scopes")
	}
	for _, n := range s.scopes() {
		if n == name {
			return filepath.Join(s.Config.ScopesDir, n), nil
		}
	}
	return "", fmt.Errorf("unknown scope %q (list_scopes)", name)
}

// allowedPath resolves symlinks and requires the result under a target root.
func (s *Server) allowedPath(p string) (string, error) {
	if len(s.Config.TargetRoots) == 0 {
		return "", errors.New("no target roots configured in ~/.burner/mcp.yaml (target_roots)")
	}
	real, err := filepath.EvalSymlinks(expandHome(p))
	if err != nil {
		return "", fmt.Errorf("target %q not found", p)
	}
	real, _ = filepath.Abs(real)
	for _, root := range s.Config.TargetRoots {
		rr, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		rr, _ = filepath.Abs(rr)
		if real == rr || strings.HasPrefix(real, rr+string(os.PathSeparator)) {
			return real, nil
		}
	}
	return "", fmt.Errorf("target %q is outside the allowed target roots", p)
}

// allowedRepo parses a repo source strictly and requires its owner (or
// owner/repo) in allow_repos.
func (s *Server) allowedRepo(src string) error {
	owner, repo, err := ParseRepo(src)
	if err != nil {
		return err
	}
	for _, a := range s.Config.AllowRepos {
		if strings.EqualFold(a, owner) || strings.EqualFold(a, owner+"/"+repo) {
			return nil
		}
	}
	return fmt.Errorf("repo %q is not in allow_repos (~/.burner/mcp.yaml)", src)
}

var (
	ownerRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)
	repoRE  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	refRE   = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,200}$`)
	// registry/name[:tag][@sha256:…], lowercase path components.
	imageRef = regexp.MustCompile(`^(?:[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]{1,5})?/)?[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$`)
)

// ParseRepo accepts owner/repo[@ref], https://github.com/owner/repo[.git][@ref]
// and git@github.com:owner/repo[.git][@ref]. Only github.com; no dot
// segments, no option-like refs.
func ParseRepo(src string) (owner, repo string, err error) {
	bad := func() (string, string, error) {
		return "", "", fmt.Errorf("invalid repo %q (use owner/repo[@ref])", src)
	}
	body, ref := src, ""
	if i := strings.LastIndex(src, "@"); i > 0 && !strings.HasPrefix(src[i:], "@github.com") {
		body, ref = src[:i], src[i+1:]
		if !refRE.MatchString(ref) || strings.HasPrefix(ref, "-") || strings.Contains(ref, "..") {
			return bad()
		}
	}
	switch {
	case strings.HasPrefix(body, "https://"):
		u, perr := url.Parse(body)
		if perr != nil || u.Host != "github.com" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return bad()
		}
		body = strings.TrimPrefix(u.Path, "/")
	case strings.HasPrefix(body, "git@github.com:"):
		body = strings.TrimPrefix(body, "git@github.com:")
	case strings.Contains(body, "://") || strings.HasPrefix(body, "-"):
		return bad()
	}
	body = strings.TrimSuffix(strings.TrimSuffix(body, "/"), ".git")
	parts := strings.Split(body, "/")
	if len(parts) != 2 || !ownerRE.MatchString(parts[0]) || !repoRE.MatchString(parts[1]) || parts[1] == "." || parts[1] == ".." {
		return bad()
	}
	return parts[0], parts[1], nil
}

// MaxPrompt caps the operator notes a client may pass.
const MaxPrompt = 8 << 10

func looksLikePath(v string) bool {
	if strings.HasPrefix(v, "~") || strings.HasPrefix(v, "/") || strings.HasPrefix(v, ".") {
		return true
	}
	for _, ext := range []string{".tar", ".tgz", ".tar.gz", ".oci"} {
		if strings.HasSuffix(v, ext) {
			return true
		}
	}
	if _, err := os.Stat(expandHome(v)); err == nil {
		return true
	}
	return false
}

// existsUnder reports whether v names a file relative to dir.
func existsUnder(dir, v string) bool {
	if dir == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(dir, v))
	return err == nil
}

func looksLikeRepo(v string) bool {
	if looksLikePath(v) {
		return false
	}
	_, _, err := ParseRepo(v)
	return err == nil
}

func (s *Server) start(r catalog.Recipe, o engine.RunOptions) (any, error) {
	s.mu.Lock()
	running := 0
	for _, st := range s.runs {
		if st.Status == "running" {
			running++
		}
	}
	if running >= s.Config.MaxRunning {
		s.mu.Unlock()
		return nil, fmt.Errorf("max_running (%d) reached", s.Config.MaxRunning)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	id := time.Now().UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b)
	dir := filepath.Join(s.Home, "mcp-runs", id)
	st := &runState{ID: id, Recipe: r.ID, Owner: s.Client, Dir: dir, Started: time.Now().UTC(), Status: "running"}
	s.runs[id] = st
	s.mu.Unlock()

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	o.RunsDir = filepath.Join(dir, "runs")
	o.Events = "-"
	if o.OnAsk == "" {
		o.OnAsk = "timeout=30m"
	}
	log, err := os.Create(filepath.Join(dir, "events.ndjson"))
	if err != nil {
		return nil, err
	}
	go func() {
		defer log.Close()
		code, err := s.Exec(context.Background(), s.Root, o.Args(), log)
		s.mu.Lock()
		defer s.mu.Unlock()
		st.Finished, st.ExitCode, st.Status = time.Now().UTC(), code, "done"
		if err != nil || code != 0 {
			st.Status = "failed"
		}
	}()
	return map[string]any{"run_id": id, "status": "running"}, nil
}

// owned returns a run only to the client that started it; other ids look
// unknown so a client cannot probe for other clients' runs.
func (s *Server) owned(args map[string]any) (*runState, error) {
	id, _ := args["run_id"].(string)
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.runs[id]
	if !ok || st.Owner != s.Client {
		return nil, fmt.Errorf("unknown run %q", id)
	}
	return st, nil
}

func recipeRef(r catalog.Recipe) string {
	if r.Source == catalog.User {
		return "mine/" + r.Name
	}
	return r.ID
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}
