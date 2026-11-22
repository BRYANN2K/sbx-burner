package sandboxes

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestKeepListBurn(t *testing.T) {
	home := t.TempDir()
	now := time.Now()
	if err := Add(home, Entry{Name: "lab-secrets-scan-012942", Recipe: "devsecops/secrets-scan", Agent: "codex", Created: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := Add(home, Entry{Name: "lab-gone-010000", Created: now}); err != nil {
		t.Fatal(err)
	}
	if err := Add(home, Entry{Name: "claude-un-dossier"}); err == nil {
		t.Fatal("a non-burner sandbox was recorded")
	}
	st, _ := os.Stat(filepath.Join(home, "sandboxes.json"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("registry mode %v", st.Mode())
	}
	ls := func(context.Context) (map[string]string, error) {
		return map[string]string{"lab-secrets-scan-012942": "stopped", "claude-un-dossier": "running", "lab-other-1": "running"}, nil
	}
	kept, err := List(context.Background(), home, ls)
	if err != nil || len(kept) != 1 || kept[0].Name != "lab-secrets-scan-012942" || kept[0].State != "stopped" {
		t.Fatalf("kept %+v %v", kept, err)
	}
	if l, _ := Load(home); len(l) != 1 {
		t.Fatal("a sandbox sbx no longer knows stayed in the registry")
	}
	var removed []string
	rm := func(_ context.Context, n string) error { removed = append(removed, n); return nil }
	if err := Burn(context.Background(), home, "lab-other-1", rm); err == nil {
		t.Fatal("burned a sandbox burner did not keep")
	}
	if err := Burn(context.Background(), home, "claude-un-dossier", rm); err == nil {
		t.Fatal("burned a non-lab sandbox")
	}
	if err := Burn(context.Background(), home, "lab-secrets-scan-012942", rm); err != nil || len(removed) != 1 {
		t.Fatalf("burn: %v %v", err, removed)
	}
	if l, _ := Load(home); len(l) != 0 {
		t.Fatal("a burned sandbox stayed in the registry")
	}
	// A failing sbx rm keeps the entry.
	_ = Add(home, Entry{Name: "lab-x-000001"})
	if err := Burn(context.Background(), home, "lab-x-000001", func(context.Context, string) error { return errors.New("boom") }); err == nil {
		t.Fatal("no error from a failing rm")
	}
	if l, _ := Load(home); len(l) != 1 {
		t.Fatal("entry lost after a failed burn")
	}
}

func TestAge(t *testing.T) {
	now := time.Now()
	for d, want := range map[time.Duration]string{5 * time.Minute: "5m", 3 * time.Hour: "3h", 72 * time.Hour: "3d"} {
		if got := Age(now.Add(-d), now); got != want {
			t.Errorf("%v: %s", d, got)
		}
	}
}
