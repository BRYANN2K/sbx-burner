// Package catalog finds and loads recipes: the official catalog (a checkout
// of this repository) and the user's own recipes under ~/.burner/recipes.
package catalog

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/BRYANN2K/sbx-burner/internal/sanitize"
)

// Source tells where a recipe comes from.
type Source string

const (
	Official Source = "official"
	User     Source = "user"
	Team     Source = "team" // a catalog added with `burner catalog add`
)

// Recipe is the part of the recipe contract the CLI needs: RECIPE.md
// frontmatter plus recipe.yaml. The runner owns the rest.
type Recipe struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Name     string `json:"name"`
	Dir      string `json:"dir"`
	Source   Source `json:"source"`

	Summary    string   `json:"summary"`
	Risk       string   `json:"risk"`
	Time       string   `json:"time"`
	TestedWith []string `json:"tested_with,omitempty"`
	Status     string   `json:"status"`

	Scope      string   `json:"scope"`       // required | optional | none
	TargetMode string   `json:"target_mode"` // required | optional | none
	Targets    []string `json:"targets"`     // path | repo | app | image | port | url
	Image      string   `json:"image,omitempty"`
}

// Accepts reports whether the recipe takes a target kind.
func (r Recipe) Accepts(kind string) bool {
	for _, k := range r.Targets {
		if k == kind {
			return true
		}
	}
	return false
}

// EngineRef is what the engine needs to find the recipe: the id for the
// official catalog, the directory for user and team recipes.
func (r Recipe) EngineRef() string {
	if r.Source == Official {
		return r.ID
	}
	return r.Dir
}

// Runnable is false for planned stubs.
func (r Recipe) Runnable() bool { return r.Status != "planned" }

type frontmatter struct {
	Name       string   `yaml:"name"`
	Category   string   `yaml:"category"`
	Summary    string   `yaml:"summary"`
	Risk       string   `yaml:"risk"`
	Time       string   `yaml:"time"`
	TestedWith []string `yaml:"tested_with"`
	Status     string   `yaml:"status"`
}

type recipeYAML struct {
	Scope    string `yaml:"scope"`
	Variants struct {
		Linux struct {
			Image string `yaml:"image"`
		} `yaml:"linux"`
	} `yaml:"variants"`
	Run struct {
		Target  string   `yaml:"target"`
		Targets []string `yaml:"targets"`
	} `yaml:"run"`
}

// ErrNoCatalog means no official catalog checkout was found.
var ErrNoCatalog = errors.New("no recipe catalog found")

// FindRoot returns the catalog root: the explicit path (--catalog), then
// $BURNER_CATALOG, then ~/.burner/catalog. It never looks at the current
// directory: the engine imports Python from the root, and a folder can fake
// anything about itself, including its git origin.
func FindRoot(explicit string) (string, error) {
	for _, dir := range []string{explicit, os.Getenv("BURNER_CATALOG")} {
		if dir != "" && isCatalog(dir) {
			return absOr(dir), nil
		}
	}
	if home := Home(); home != "" && isCatalog(filepath.Join(home, "catalog")) {
		return filepath.Join(home, "catalog"), nil
	}
	return "", ErrNoCatalog
}

func absOr(dir string) string {
	if abs, err := filepath.Abs(dir); err == nil {
		return abs
	}
	return dir
}

func isCatalog(dir string) bool {
	for _, sub := range []string{"recipes", "lab", "template"} {
		if st, err := os.Stat(filepath.Join(dir, sub)); err != nil || !st.IsDir() {
			return false
		}
	}
	return true
}

// Home is burner's state directory (~/.burner, or $BURNER_HOME).
func Home() string {
	if env := os.Getenv("BURNER_HOME"); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".burner")
}

// UserRecipesDir is where `burner new` writes recipes.
func UserRecipesDir() string {
	if h := Home(); h != "" {
		return filepath.Join(h, "recipes")
	}
	return ""
}

// Load reads every recipe of the official catalog and of the user's
// directory. A recipe that fails to parse is reported, not fatal.
func Load(root string) ([]Recipe, []error) {
	var recipes []Recipe
	var problems []error
	if root != "" {
		r, p := loadDir(filepath.Join(root, "recipes"), Official)
		recipes, problems = append(recipes, r...), append(problems, p...)
	}
	if home := Home(); home != "" {
		teams, _ := os.ReadDir(filepath.Join(home, "catalogs"))
		for _, t := range teams {
			if t.IsDir() {
				r, p := loadDir(filepath.Join(home, "catalogs", t.Name(), "recipes"), Team)
				recipes, problems = append(recipes, r...), append(problems, p...)
			}
		}
	}
	if dir := UserRecipesDir(); dir != "" {
		r, p := loadDir(dir, User)
		recipes, problems = append(recipes, r...), append(problems, p...)
	}
	// An official id cannot be shadowed: user and team recipes that reuse
	// one are dropped and reported.
	seen := map[string]Source{}
	kept := recipes[:0]
	for _, r := range recipes {
		if r.Source == Official {
			seen[r.ID] = Official
		}
	}
	for _, r := range recipes {
		if r.Source != Official {
			if src, dup := seen[r.ID]; dup {
				problems = append(problems, fmt.Errorf("%s recipe %s ignored: the id is already used by a %s recipe (rename it)", r.Source, r.ID, src))
				continue
			}
			seen[r.ID] = r.Source
		}
		kept = append(kept, r)
	}
	recipes = kept
	sort.SliceStable(recipes, func(i, j int) bool {
		if recipes[i].Source != recipes[j].Source {
			return recipes[i].Source == User
		}
		return recipes[i].ID < recipes[j].ID
	})
	return recipes, problems
}

func loadDir(dir string, source Source) ([]Recipe, []error) {
	cats, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, []error{err}
	}
	var out []Recipe
	var problems []error
	for _, c := range cats {
		if !c.IsDir() || strings.HasPrefix(c.Name(), ".") {
			continue
		}
		names, err := os.ReadDir(filepath.Join(dir, c.Name()))
		if err != nil {
			problems = append(problems, err)
			continue
		}
		for _, n := range names {
			if !n.IsDir() || strings.HasPrefix(n.Name(), ".") {
				continue
			}
			path := filepath.Join(dir, c.Name(), n.Name())
			r, err := LoadRecipe(path, source)
			if err != nil {
				problems = append(problems, err)
				continue
			}
			out = append(out, r)
		}
	}
	return out, problems
}

// LoadRecipe reads one recipe directory.
func LoadRecipe(path string, source Source) (Recipe, error) {
	category, name := filepath.Base(filepath.Dir(path)), filepath.Base(path)
	r := Recipe{ID: category + "/" + name, Category: category, Name: name, Dir: path, Source: source}

	md, err := os.ReadFile(filepath.Join(path, "RECIPE.md"))
	if err != nil {
		return r, fmt.Errorf("%s: %w", r.ID, err)
	}
	fm, err := parseFrontmatter(md)
	if err != nil {
		return r, fmt.Errorf("%s: RECIPE.md: %w", r.ID, err)
	}
	// Team catalogs are third-party text: clean what reaches the terminal.
	r.Summary, r.Risk, r.Time, r.Status = sanitize.Line(fm.Summary, 300), sanitize.Line(fm.Risk, 20), sanitize.Line(fm.Time, 20), sanitize.Line(fm.Status, 20)
	for _, a := range fm.TestedWith {
		r.TestedWith = append(r.TestedWith, sanitize.Line(a, 40))
	}

	raw, err := os.ReadFile(filepath.Join(path, "recipe.yaml"))
	if err != nil {
		return r, fmt.Errorf("%s: %w", r.ID, err)
	}
	var cfg recipeYAML
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return r, fmt.Errorf("%s: recipe.yaml: %w", r.ID, err)
	}
	r.Scope = orDefault(cfg.Scope, "none")
	r.TargetMode = orDefault(cfg.Run.Target, "none")
	r.Targets = cfg.Run.Targets
	if r.Targets == nil && r.TargetMode != "none" {
		r.Targets = []string{"path"} // same default as the Python runner
	}
	r.Image = cfg.Variants.Linux.Image
	return r, nil
}

func parseFrontmatter(md []byte) (frontmatter, error) {
	var fm frontmatter
	md = bytes.TrimPrefix(md, []byte("\xef\xbb\xbf"))
	if !bytes.HasPrefix(md, []byte("---")) {
		return fm, errors.New("missing frontmatter")
	}
	rest := md[3:]
	end := bytes.Index(rest, []byte("\n---"))
	if end < 0 {
		return fm, errors.New("unterminated frontmatter")
	}
	if err := yaml.Unmarshal(rest[:end], &fm); err != nil {
		// The engine's parser (lab/miniyaml) reads `key: value` lines
		// leniently, so a summary like "risk: install scripts" is valid
		// there. Read the same way here rather than drop the recipe.
		return lenientFrontmatter(rest[:end]), nil
	}
	return fm, nil
}

// lenientFrontmatter reads top-level `key: value` lines: the first ": "
// splits key and value, `[a, b]` is a list, quotes are trimmed.
func lenientFrontmatter(raw []byte) frontmatter {
	var fm frontmatter
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == '#' {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		switch strings.TrimSpace(key) {
		case "name":
			fm.Name = value
		case "category":
			fm.Category = value
		case "summary":
			fm.Summary = value
		case "risk":
			fm.Risk = value
		case "time":
			fm.Time = value
		case "status":
			fm.Status = value
		case "tested_with":
			for _, a := range strings.Split(strings.Trim(value, "[]"), ",") {
				if a = strings.TrimSpace(a); a != "" {
					fm.TestedWith = append(fm.TestedWith, a)
				}
			}
		}
	}
	return fm
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// Find returns the recipe whose id is ref, or whose name is ref when that
// name is unique.
func Find(recipes []Recipe, ref string) (Recipe, error) {
	var byName []Recipe
	for _, r := range recipes {
		if r.ID == ref {
			return r, nil
		}
		if r.Name == ref {
			byName = append(byName, r)
		}
	}
	switch len(byName) {
	case 1:
		return byName[0], nil
	case 0:
		return Recipe{}, fmt.Errorf("unknown recipe %q (burner list shows them)", ref)
	default:
		ids := make([]string, len(byName))
		for i, r := range byName {
			ids[i] = r.ID
		}
		return Recipe{}, fmt.Errorf("recipe name %q is ambiguous: %s", ref, strings.Join(ids, ", "))
	}
}

// Categories returns the categories present, in a stable display order.
func Categories(recipes []Recipe) []string {
	order := []string{"mine", "devsecops", "pentest", "malware", "detection", "hardening", "ir", "ai-security", "dev", "ci", "web", "cu"}
	seen := map[string]bool{}
	for _, r := range recipes {
		if r.Runnable() {
			seen[DisplayCategory(r)] = true
		}
	}
	var out []string
	for _, c := range order {
		if seen[c] {
			out = append(out, c)
			delete(seen, c)
		}
	}
	var extra []string
	for c := range seen {
		extra = append(extra, c)
	}
	sort.Strings(extra)
	return append(out, extra...)
}

// DisplayCategory groups user recipes under "mine".
func DisplayCategory(r Recipe) string {
	if r.Source == User {
		return "mine"
	}
	return r.Category
}
