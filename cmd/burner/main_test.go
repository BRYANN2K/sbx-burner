package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/BRYANN2K/sbx-burner/internal/catalog"
	"github.com/BRYANN2K/sbx-burner/internal/engine"
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
