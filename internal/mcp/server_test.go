package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// catalogRoot builds a one-recipe catalog: pentest/web-x needs a scope and a
// target; devsecops/scan takes a path.
func catalogRoot(t *testing.T) string {
	root := t.TempDir()
	for _, d := range []string{"lab", "template"} {
		os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	add := func(cat, name, yaml string) {
		dir := filepath.Join(root, "recipes", cat, name)
		os.MkdirAll(dir, 0o755)
		os.WriteFile(filepath.Join(dir, "RECIPE.md"), []byte("---\nname: "+name+"\nstatus: beta\n---\n"), 0o644)
		os.WriteFile(filepath.Join(dir, "recipe.yaml"), []byte(yaml), 0o644)
	}
	add("pentest", "web-x", "scope: required\nrun:\n  target: required\n  targets: [image, port, url, demo]\n")
	add("devsecops", "scan", "scope: none\nrun:\n  target: required\n  targets: [path]\n")
	return root
}

type harness struct {
	t     *testing.T
	in    *io.PipeWriter
	out   *bufio.Scanner
	calls *[][]string
	id    int
}

func newHarness(t *testing.T, cfg Config) *harness {
	home := t.TempDir()
	t.Setenv("BURNER_HOME", filepath.Join(home, "nohome"))
	if cfg.ScopesDir == "" {
		cfg.ScopesDir = filepath.Join(home, "scopes")
	}
	os.MkdirAll(cfg.ScopesDir, 0o700)
	os.WriteFile(filepath.Join(cfg.ScopesDir, "lab.yaml"), []byte("id: lab\n"), 0o600)
	if cfg.MaxRunning == 0 {
		cfg.MaxRunning = 1
	}
	calls := [][]string{}
	s := &Server{Root: catalogRoot(t), Home: home, Config: cfg, Client: "client-a", Version: "test",
		Exec: func(_ context.Context, _ string, args []string, w io.Writer) (int, error) {
			calls = append(calls, args)
			io.WriteString(w, "plan\n")
			return 0, nil
		}}
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	go func() { s.Serve(context.Background(), inR, outW); outW.Close() }()
	return &harness{t: t, in: inW, out: bufio.NewScanner(outR), calls: &calls}
}

func (h *harness) call(tool string, args map[string]any) (map[string]any, bool) {
	h.id++
	req, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": h.id, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args}})
	h.in.Write(append(req, '\n'))
	if !h.out.Scan() {
		h.t.Fatal("no response")
	}
	var resp struct {
		Result struct {
			StructuredContent map[string]any `json:"structuredContent"`
			IsError           bool           `json:"isError"`
		} `json:"result"`
	}
	json.Unmarshal(h.out.Bytes(), &resp)
	return resp.Result.StructuredContent, resp.Result.IsError
}

func errText(m map[string]any) string { s, _ := m["error"].(string); return s }

func TestScopeIsPickedNeverPassed(t *testing.T) {
	h := newHarness(t, Config{AllowImages: true})
	for _, bad := range []string{"../etc/passwd", "/tmp/my-scope.yaml", "evil.yaml", ".hidden.yaml"} {
		res, isErr := h.call("plan_run", map[string]any{"recipe": "web-x", "scope": bad, "demo": true})
		if !isErr {
			t.Fatalf("scope %q accepted: %v", bad, res)
		}
	}
	if _, isErr := h.call("plan_run", map[string]any{"recipe": "web-x", "scope": "lab.yaml", "demo": true}); isErr {
		t.Fatal("listed scope refused")
	}
}

func TestNoToolWritesOrWidensScope(t *testing.T) {
	h := newHarness(t, Config{})
	h.id++
	req, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": h.id, "method": "tools/list"})
	h.in.Write(append(req, '\n'))
	h.out.Scan()
	body := strings.ToLower(h.out.Text())
	for _, forbidden := range []string{"write_scope", "set_scope", "create_scope", "shell", "exec_command", "read_file"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("tool list exposes %q", forbidden)
		}
	}
}

func TestPathTargetsStayUnderRoots(t *testing.T) {
	allowed := t.TempDir()
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret"), []byte("x"), 0o600)
	link := filepath.Join(allowed, "link")
	os.Symlink(outside, link)
	h := newHarness(t, Config{TargetRoots: []string{allowed}})
	if _, isErr := h.call("plan_run", map[string]any{"recipe": "scan", "target": allowed}); isErr {
		t.Fatal("allowed root refused")
	}
	for _, bad := range []string{outside, link, filepath.Join(allowed, "..")} {
		if res, isErr := h.call("plan_run", map[string]any{"recipe": "scan", "target": bad}); !isErr {
			t.Fatalf("target %q accepted: %v", bad, res)
		}
	}
}

func TestNoRootsMeansNoPathTargets(t *testing.T) {
	h := newHarness(t, Config{})
	res, isErr := h.call("plan_run", map[string]any{"recipe": "scan", "target": t.TempDir()})
	if !isErr || !strings.Contains(errText(res), "target_roots") {
		t.Fatalf("got %v", res)
	}
}

func TestImagesAndURLsOffByDefault(t *testing.T) {
	h := newHarness(t, Config{})
	if res, isErr := h.call("plan_run", map[string]any{"recipe": "web-x", "scope": "lab.yaml", "target_image": "nginx:1"}); !isErr {
		t.Fatalf("image accepted: %v", res)
	}
	if res, isErr := h.call("plan_run", map[string]any{"recipe": "web-x", "scope": "lab.yaml", "target_url": "https://x.test"}); !isErr {
		t.Fatalf("url accepted: %v", res)
	}
}

func TestRunsAreOwnedByTheirClient(t *testing.T) {
	h := newHarness(t, Config{})
	res, isErr := h.call("run", map[string]any{"recipe": "web-x", "scope": "lab.yaml", "demo": true})
	if isErr {
		t.Fatalf("run refused: %v", res)
	}
	id, _ := res["run_id"].(string)
	if _, isErr := h.call("run_status", map[string]any{"run_id": id}); isErr {
		t.Fatal("owner cannot read its run")
	}
	if _, isErr := h.call("run_status", map[string]any{"run_id": "someone-elses"}); !isErr {
		t.Fatal("unknown run id accepted")
	}
}

func TestClientTokenIgnoresClientInfo(t *testing.T) {
	t.Setenv("BURNER_CLIENT", "")
	a, b := ClientToken(), ClientToken()
	if a == b || len(a) != 32 {
		t.Fatalf("tokens not random: %q %q", a, b)
	}
	t.Setenv("BURNER_CLIENT", "ci-bot")
	if ClientToken() != "ci-bot" {
		t.Fatal("BURNER_CLIENT not used")
	}
}

func TestMissingConfigIsStrict(t *testing.T) {
	cfg, err := LoadConfig(t.TempDir())
	if err != nil || len(cfg.TargetRoots) != 0 || cfg.AllowImages || cfg.AllowURLs || cfg.MaxRunning != 1 {
		t.Fatalf("defaults not strict: %+v %v", cfg, err)
	}
}

func TestRepoSourcesAreParsedStrictly(t *testing.T) {
	h := newHarness(t, Config{AllowRepos: []string{"acme"}})
	for _, bad := range []string{"acme/../evil/repo", "https://github.com/acme/../evil/repo", "acme/repo@--upload-pack=touch /tmp/p",
		"https://evil.com/acme/repo", "https://tok@github.com/acme/repo", "ext::sh -c id", "acme/repo@a..b", "evil/repo"} {
		if res, isErr := h.call("plan_run", map[string]any{"recipe": "web-x", "scope": "lab.yaml", "target_repo": bad}); !isErr {
			t.Fatalf("repo %q accepted: %v", bad, res)
		}
	}
	for _, ok := range []string{"acme/repo", "acme/repo@main", "https://github.com/acme/repo.git", "git@github.com:acme/repo.git@v1.2"} {
		if _, _, err := ParseRepo(ok); err != nil {
			t.Fatalf("%q refused: %v", ok, err)
		}
	}
}

func TestImageTarballsFollowTargetRoots(t *testing.T) {
	allowed := t.TempDir()
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret.tgz"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(allowed, "app.tar"), []byte("x"), 0o600)
	h := newHarness(t, Config{AllowImages: true, TargetRoots: []string{allowed}})
	for _, bad := range []string{filepath.Join(outside, "secret.tgz"), "~/secret.tgz", "x.oci", allowed, "Bad/Ref", "nginx;rm -rf"} {
		if res, isErr := h.call("plan_run", map[string]any{"recipe": "web-x", "scope": "lab.yaml", "target_image": bad}); !isErr {
			t.Fatalf("image %q accepted: %v", bad, res)
		}
	}
	for _, ok := range []string{filepath.Join(allowed, "app.tar"), "ghcr.io/acme/app:1.2", "nginx", "localhost:5000/x/y@sha256:" + strings.Repeat("a", 64)} {
		if res, isErr := h.call("plan_run", map[string]any{"recipe": "web-x", "scope": "lab.yaml", "target_image": ok}); isErr {
			t.Fatalf("image %q refused: %v", ok, res)
		}
	}
}

func TestPrefixSiblingRootIsOutside(t *testing.T) {
	base := t.TempDir()
	allowed := filepath.Join(base, "work")
	sibling := filepath.Join(base, "work-secrets")
	os.MkdirAll(allowed, 0o755)
	os.MkdirAll(sibling, 0o755)
	h := newHarness(t, Config{TargetRoots: []string{allowed}})
	if res, isErr := h.call("plan_run", map[string]any{"recipe": "scan", "target": sibling}); !isErr {
		t.Fatalf("prefix sibling accepted: %v", res)
	}
	if res, isErr := h.call("plan_run", map[string]any{"recipe": "scan", "target": "relative/dir"}); !isErr {
		t.Fatalf("relative path accepted: %v", res)
	}
}

func TestPromptIsCapped(t *testing.T) {
	h := newHarness(t, Config{})
	if res, isErr := h.call("plan_run", map[string]any{"recipe": "web-x", "scope": "lab.yaml", "demo": true, "prompt": strings.Repeat("x", MaxPrompt+1)}); !isErr {
		t.Fatalf("oversized prompt accepted: %v", res)
	}
	if _, isErr := h.call("plan_run", map[string]any{"recipe": "web-x", "scope": "lab.yaml", "demo": true, "prompt": "focus on auth"}); isErr {
		t.Fatal("normal prompt refused")
	}
}

func TestRelativeExistingPathIsNotAnImageRef(t *testing.T) {
	h := newHarness(t, Config{AllowImages: true, TargetRoots: []string{t.TempDir()}})
	// "recipes/pentest/web-x" exists under the catalog root of the harness.
	if res, isErr := h.call("plan_run", map[string]any{"recipe": "web-x", "scope": "lab.yaml", "target_image": "recipes/pentest/web-x"}); !isErr {
		t.Fatalf("relative existing path passed as image ref: %v", res)
	}
}

func TestForeignRunIDsForEventsAndAnswer(t *testing.T) {
	h := newHarness(t, Config{})
	for _, tool := range []string{"run_events", "answer", "get_report"} {
		if res, isErr := h.call(tool, map[string]any{"run_id": "not-mine", "ask_id": "a1", "value": "x"}); !isErr {
			t.Fatalf("%s accepted a foreign run: %v", tool, res)
		}
	}
}
