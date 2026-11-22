package scaffold

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewReplacesPlaceholders(t *testing.T) {
	tpl := t.TempDir()
	os.MkdirAll(filepath.Join(tpl, "skills", "__NAME__"), 0o755)
	os.WriteFile(filepath.Join(tpl, "RECIPE.md"), []byte("name: __NAME__\ncategory: __CATEGORY__\n"), 0o644)
	os.WriteFile(filepath.Join(tpl, "skills", "__NAME__", "SKILL.md"), []byte("# __NAME__"), 0o644)
	dest, err := New(tpl, t.TempDir(), "devsecops", "my-scan")
	if err != nil {
		t.Fatal(err)
	}
	md, _ := os.ReadFile(filepath.Join(dest, "RECIPE.md"))
	if !strings.Contains(string(md), "name: my-scan") || !strings.Contains(string(md), "category: devsecops") {
		t.Fatalf("RECIPE.md = %q", md)
	}
	if _, err := os.Stat(filepath.Join(dest, "skills", "my-scan", "SKILL.md")); err != nil {
		t.Fatal("skill dir not renamed")
	}
	if _, err := New(tpl, filepath.Dir(filepath.Dir(dest)), "devsecops", "my-scan"); err == nil {
		t.Fatal("must refuse to overwrite")
	}
}

func TestNewRejectsBadInput(t *testing.T) {
	for _, c := range [][2]string{{"devsecops", "Bad_Name"}, {"apple", "x"}, {"nope", "x"}} {
		if _, err := New(t.TempDir(), t.TempDir(), c[0], c[1]); err == nil {
			t.Fatalf("accepted %v", c)
		}
	}
}
