package series

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BRYANN2K/sbx-burner/internal/catalog"
	"github.com/BRYANN2K/sbx-burner/internal/engine"
)

func TestSaveLoadList(t *testing.T) {
	home := t.TempDir()
	s := Series{Name: "Web Audit Shop", Items: []Item{{Recipe: "pentest/web-recon", Agent: "codex", Model: "gpt-6-luna"}, {Recipe: "pentest/dast-light", Agent: "claude"}}}
	p, err := Save(home, s)
	if err != nil || filepath.Base(p) != "web-audit-shop.json" {
		t.Fatalf("save: %s %v", p, err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	got, err := Load(home, "web-audit-shop")
	if err != nil || len(got.Items) != 2 || got.OnFailure != "continue" || got.Items[0].Model != "gpt-6-luna" {
		t.Fatalf("load: %+v %v", got, err)
	}
	if l := List(home); len(l) != 1 || l[0].Name != "web-audit-shop" {
		t.Fatalf("list %+v", l)
	}
	if _, err := Save(home, Series{Name: "x"}); err == nil {
		t.Fatal("an empty series was saved")
	}
	if _, err := Load(home, "../etc/passwd"); err == nil {
		t.Fatal("a path was accepted as a name")
	}
}

func writeReport(t *testing.T, dir, body string) string {
	t.Helper()
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "report.json"), []byte(body), 0o600)
	md := filepath.Join(dir, "report.md")
	os.WriteFile(md, []byte("# r\n"), 0o600)
	return md
}

func TestMergeDeduplicatesWithSources(t *testing.T) {
	root := t.TempDir()
	a := writeReport(t, filepath.Join(root, "a"), `{"findings":[{"id":"basket-idor","title":"Basket IDOR","severity":"high"},{"id":"xss","title":"Search  reflected XSS","severity":"medium"}]}`)
	b := writeReport(t, filepath.Join(root, "b"), `{"findings":[{"id":"x-1","title":"search reflected xss","severity":"high"},{"id":"m","title":"Admin metrics without auth","severity":"high"}]}`)
	results := []RecipeResult{{Recipe: "pentest/webapp-blackbox", Report: a}, {Recipe: "pentest/dast-light", Report: b}, {Recipe: "pentest/web-recon", Status: "skipped"}}
	fs := Merge(results)
	if len(fs) != 3 {
		t.Fatalf("merged %+v", fs)
	}
	var xss Finding
	for _, f := range fs {
		if f.ID == "xss" {
			xss = f
		}
	}
	if strings.Join(xss.Sources, ",") != "pentest/webapp-blackbox,pentest/dast-light" || xss.Severity != "high" {
		t.Fatalf("xss %+v", xss)
	}
	if results[0].Findings != 2 || results[1].Findings != 2 {
		t.Fatalf("counts %+v", results)
	}
	out, err := Write(filepath.Join(root, "series"), Combined{Series: "web", Target: "http://localhost:3000", Recipes: results, Findings: fs})
	if err != nil {
		t.Fatal(err)
	}
	md, _ := os.ReadFile(out)
	if !strings.Contains(string(md), "pentest/webapp-blackbox, pentest/dast-light") || !strings.Contains(string(md), "skipped") {
		t.Fatalf("report.md:\n%s", md)
	}
}

func TestPrepareSkipsRecipesWithoutTheSharedTarget(t *testing.T) {
	recipes := []catalog.Recipe{
		{ID: "pentest/web-recon", Category: "pentest", Name: "web-recon", Source: catalog.Official, Scope: "required", Targets: []string{"app", "url"}},
		{ID: "devsecops/secrets-scan", Category: "devsecops", Name: "secrets-scan", Source: catalog.Official, Scope: "none", Targets: []string{"path", "repo"}},
	}
	s := Series{Name: "x", Items: []Item{{Recipe: "pentest/web-recon", Agent: "codex", Model: "gpt-6-luna"}, {Recipe: "devsecops/secrets-scan", Agent: "claude", Model: "m"}}, Keep: true}
	plans := Prepare(s, recipes, engine.RunOptions{TargetURL: "http://localhost:3000", Scope: "/s.yaml"}, []string{"codex"})
	if plans[0].Skip != "" || !plans[0].Opts.ACP || plans[0].Opts.Model != "gpt-6-luna" || plans[0].Opts.Scope != "/s.yaml" || !plans[0].Opts.Keep || plans[0].Opts.OnAsk != "skip" {
		t.Fatalf("plan 0 %+v", plans[0])
	}
	if plans[1].Skip != "no shared target" {
		t.Fatalf("plan 1 %+v", plans[1])
	}
	root := t.TempDir()
	rep := writeReport(t, filepath.Join(root, "r1"), `{"findings":[{"id":"a","title":"A","severity":"low"}]}`)
	var seen []string
	c, path, err := Run(context.Background(), s, plans, "http://localhost:3000", root, func(_ context.Context, o engine.RunOptions) (string, int, error) {
		return rep, 0, nil
	}, func(i int, r RecipeResult) { seen = append(seen, fmt.Sprintf("%d:%s", i, r.Status)) })
	if err != nil || len(c.Findings) != 1 || c.Recipes[1].Status != "skipped" || !strings.HasSuffix(path, "report.md") {
		t.Fatalf("run %+v %s %v", c, path, err)
	}
	if strings.Join(seen, " ") != "0:running 0:done 1:skipped" {
		t.Fatalf("progress %v", seen)
	}
}

func TestReportCellsAreCleaned(t *testing.T) {
	if got := mdCell("evil\x1b[31m | title\nnext"); strings.ContainsAny(got, "\x1b\n") || !strings.Contains(got, "\\|") {
		t.Fatalf("cell %q", got)
	}
}
