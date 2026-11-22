package catalog

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestLoadAndFind(t *testing.T) {
	t.Setenv("BURNER_HOME", t.TempDir())
	recipes, problems := Load("testdata")
	if len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
	}
	r, err := Find(recipes, "web-x")
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != "pentest/web-x" || r.Scope != "required" || r.TargetMode != "required" || !r.Accepts("port") || r.Demo == "" || r.Image != "kalilinux/kali-rolling" {
		t.Fatalf("unexpected recipe: %+v", r)
	}
	if _, err := Find(recipes, "nope"); err == nil {
		t.Fatal("expected error for unknown recipe")
	}
}

func TestDefaultTargetsMatchRunner(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "devsecops", "scan")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "RECIPE.md"), []byte("---\nname: scan\nstatus: beta\n---\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "recipe.yaml"), []byte("run:\n  target: required\n"), 0o644)
	r, err := LoadRecipe(dir, Official)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Targets) != 1 || r.Targets[0] != "path" {
		t.Fatalf("targets = %v, want [path]", r.Targets)
	}
}

func TestUserRecipesShownUnderMine(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BURNER_HOME", home)
	dir := filepath.Join(home, "recipes", "devsecops", "own")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "RECIPE.md"), []byte("---\nname: own\nstatus: beta\n---\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "recipe.yaml"), []byte("scope: none\n"), 0o644)
	recipes, _ := Load("testdata")
	if recipes[0].Source != User || DisplayCategory(recipes[0]) != "mine" {
		t.Fatalf("user recipe not first under mine: %+v", recipes[0])
	}
	if cats := Categories(recipes); cats[0] != "mine" {
		t.Fatalf("categories = %v", cats)
	}
}

func TestHostileCheckoutInCwdIsNotTheCatalog(t *testing.T) {
	hostile := t.TempDir()
	for _, d := range []string{"recipes", "lab", "template"} {
		os.MkdirAll(filepath.Join(hostile, d), 0o755)
	}
	exec.Command("git", "-C", hostile, "init", "-q").Run()
	exec.Command("git", "-C", hostile, "remote", "add", "origin", "https://github.com/evil/sbx-burner.git").Run()
	sub := filepath.Join(hostile, "deep", "dir")
	os.MkdirAll(sub, 0o755)
	t.Setenv("BURNER_CATALOG", "")
	t.Setenv("BURNER_HOME", t.TempDir())
	t.Chdir(sub)
	if root, err := FindRoot(""); err == nil {
		t.Fatalf("hostile checkout used as catalog: %s", root)
	}
	// A faked official origin must not help either.
	exec.Command("git", "-C", hostile, "remote", "set-url", "origin", "https://github.com/BRYANN2K/sbx-burner.git").Run()
	if root, err := FindRoot(""); err == nil {
		t.Fatalf("faked origin accepted: %s", root)
	}
	if _, err := FindRoot(hostile); err != nil {
		t.Fatalf("explicit --catalog refused: %v", err)
	}
}

func TestFindRootNeedsRecipesLabTemplate(t *testing.T) {
	if _, err := FindRoot("testdata"); err != nil {
		t.Fatalf("testdata should be a catalog: %v", err)
	}
	empty := t.TempDir()
	t.Setenv("BURNER_CATALOG", "")
	t.Setenv("BURNER_HOME", empty)
	t.Chdir(empty)
	if _, err := FindRoot(""); err != ErrNoCatalog {
		t.Fatalf("err = %v, want ErrNoCatalog", err)
	}
}

func TestUserRecipeCannotShadowOfficial(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BURNER_HOME", home)
	dir := filepath.Join(home, "recipes", "pentest", "web-x")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "RECIPE.md"), []byte("---\nname: web-x\nstatus: beta\n---\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "recipe.yaml"), []byte("scope: none\n"), 0o644)
	recipes, problems := Load("testdata")
	r, err := Find(recipes, "pentest/web-x")
	if err != nil || r.Source != Official || len(problems) != 1 {
		t.Fatalf("source=%v problems=%v", r.Source, problems)
	}
}

func TestFrontmatterWithColonInSummaryIsRead(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "devsecops", "scr")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "RECIPE.md"), []byte("---\nname: scr\nsummary: Assess risk: install scripts and more.\nrisk: low\ntested_with: [claude, codex]\nstatus: beta\n---\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "recipe.yaml"), []byte("scope: none\n"), 0o644)
	r, err := LoadRecipe(dir, Official)
	if err != nil || r.Summary != "Assess risk: install scripts and more." || len(r.TestedWith) != 2 || r.Status != "beta" {
		t.Fatalf("r=%+v err=%v", r, err)
	}
}
