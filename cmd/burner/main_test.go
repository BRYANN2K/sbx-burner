package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BRYANN2K/sbx-burner/internal/catalog"
	"github.com/BRYANN2K/sbx-burner/internal/engine"
	"github.com/BRYANN2K/sbx-burner/internal/sandboxes"
)

func TestMissingInputsNamesEveryRequiredInput(t *testing.T) {
	r := catalog.Recipe{ID: "pentest/x", Scope: "required", TargetMode: "required", Targets: []string{"image", "port", "url"}}
	got := strings.Join(missingInputs(r, engine.RunOptions{}), "; ")
	for _, want := range []string{"--target-image", "--target-url", "--scope"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %q", want, got)
		}
	}
	if m := missingInputs(r, engine.RunOptions{TargetImage: "nginx:1", Scope: "s.yaml"}); len(m) != 0 {
		t.Fatalf("unexpected %v", m)
	}
}

func TestReorderKeepsFlagValues(t *testing.T) {
	got := reorder([]string{"web-x", "--target-image", "img:1", "--dry-run"})
	if strings.Join(got, " ") != "--target-image img:1 --dry-run web-x" {
		t.Fatalf("got %v", got)
	}
}

func TestRunArgsMatchEngineFlags(t *testing.T) {
	args := strings.Join(engine.RunOptions{Recipe: "pentest/x", TargetImage: "ghcr.io/a/b:1", TargetPort: "8080", Agent: "claude", DryRun: true}.Args(), " ")
	for _, want := range []string{"run pentest/x", "--target-image=ghcr.io/a/b:1", "--target-port=8080", "--agent=claude", "--dry-run", "--runs-dir"} {
		if !strings.Contains(args, want) {
			t.Fatalf("missing %q in %q", want, args)
		}
	}
}

func TestScopeNewOutIsAbsolute(t *testing.T) {
	got := absPaths("scope", []string{"new", "pentest/api-greybox", "--target-port", "3000", "--out", "rel/s.yaml"})
	if !filepath.IsAbs(got[5]) || !strings.HasSuffix(got[5], "rel/s.yaml") {
		t.Fatalf("--out not made absolute: %v", got)
	}
}

func TestSandboxesAndBurnCommands(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BURNER_HOME", home)
	_ = sandboxes.Add(home, sandboxes.Entry{Name: "lab-a-000001", Recipe: "devsecops/secrets-scan", Agent: "codex", Created: time.Now()})
	_ = sandboxes.Add(home, sandboxes.Entry{Name: "lab-b-000002", Recipe: "pentest/web-recon", Agent: "codex", Created: time.Now()})
	live := map[string]string{"lab-a-000001": "stopped", "lab-b-000002": "running"}
	var removed []string
	origL, origR := sbxLister, sbxRemover
	defer func() { sbxLister, sbxRemover = origL, origR }()
	sbxLister = func(context.Context) (map[string]string, error) { return live, nil }
	sbxRemover = func(_ context.Context, n string) error { removed = append(removed, n); delete(live, n); return nil }
	var out, errb bytes.Buffer
	if code := cmdSandboxes(context.Background(), []string{"--json"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "lab-a-000001") {
		t.Fatalf("sandboxes: %d %s %s", code, out.String(), errb.String())
	}
	if code := cmdBurn(context.Background(), []string{"claude-x"}, &out, &errb); code == 0 {
		t.Fatal("burned a sandbox burner did not keep")
	}
	if code := cmdBurn(context.Background(), []string{"--kept"}, &out, &errb); code != 0 || len(removed) != 2 {
		t.Fatalf("burn --kept: %d %v", code, removed)
	}
}
