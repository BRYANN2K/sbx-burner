// Package series saves recipe series and merges their reports. A series
// runs its recipes one after the other against one target; recipes that
// cannot take that target are skipped.
package series

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/BRYANN2K/sbx-burner/internal/sanitize"
)

// Item is one recipe of a series.
type Item struct {
	Recipe string `json:"recipe"`
	Agent  string `json:"agent"`
	Model  string `json:"model,omitempty"`
}

// Series is a saved, named list of recipes.
type Series struct {
	Name      string `json:"name"`
	Items     []Item `json:"items"`
	OnFailure string `json:"on_failure"` // continue | stop
	Keep      bool   `json:"keep"`
	Saved     string `json:"saved,omitempty"`
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Slug makes a series name.
func Slug(s string) string {
	s = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(strings.ToLower(s), "-")
	return strings.Trim(s, "-")
}

func dir(home string) string { return filepath.Join(home, "series") }

// Save writes ~/.burner/series/<name>.json (0600).
func Save(home string, s Series) (string, error) {
	s.Name = Slug(s.Name)
	if !nameRE.MatchString(s.Name) {
		return "", errors.New("a series needs a name")
	}
	if len(s.Items) == 0 {
		return "", errors.New("a series needs at least one recipe")
	}
	if s.OnFailure == "" {
		s.OnFailure = "continue"
	}
	s.Saved = time.Now().UTC().Format(time.RFC3339)
	if err := os.MkdirAll(dir(home), 0o700); err != nil {
		return "", err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	p := filepath.Join(dir(home), s.Name+".json")
	f, err := os.CreateTemp(dir(home), ".tmp-*")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	_, werr := f.Write(append(b, '\n'))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return "", werr
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return "", err
	}
	return p, os.Rename(tmp, p)
}

// Load reads one saved series by name.
func Load(home, name string) (Series, error) {
	name = Slug(name)
	if !nameRE.MatchString(name) {
		return Series{}, fmt.Errorf("invalid series name %q", name)
	}
	b, err := os.ReadFile(filepath.Join(dir(home), name+".json"))
	if err != nil {
		return Series{}, fmt.Errorf("no series %q", name)
	}
	var s Series
	if len(b) > 1<<20 || json.Unmarshal(b, &s) != nil || len(s.Items) == 0 {
		return Series{}, fmt.Errorf("series %q is not readable", name)
	}
	return s, nil
}

// List returns the saved series, the most recently saved last.
func List(home string) []Series {
	entries, _ := os.ReadDir(dir(home))
	var out []Series
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if s, err := Load(home, strings.TrimSuffix(e.Name(), ".json")); err == nil {
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Saved < out[j].Saved })
	return out
}

// Finding is one merged finding with the recipes that reported it.
type Finding struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Severity string   `json:"severity"`
	Location string   `json:"location,omitempty"`
	Sources  []string `json:"sources"`
}

// RecipeResult is how one recipe of the series ended.
type RecipeResult struct {
	Recipe   string `json:"recipe"`
	Agent    string `json:"agent"`
	Model    string `json:"model,omitempty"`
	Status   string `json:"status"` // done | failed | skipped | stopped
	Reason   string `json:"reason,omitempty"`
	Report   string `json:"report,omitempty"`
	Findings int    `json:"findings"`
}

// Combined is the series report.
type Combined struct {
	Series   string         `json:"series"`
	Target   string         `json:"target"`
	Started  string         `json:"started"`
	Finished string         `json:"finished"`
	Recipes  []RecipeResult `json:"recipes"`
	Findings []Finding      `json:"findings"`
}

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

// Merge reads every recipe's report.json and merges the findings: the same
// title (case and spacing ignored) is one finding with several sources.
func Merge(results []RecipeResult) []Finding {
	byKey := map[string]*Finding{}
	var order []string
	for i := range results {
		r := &results[i]
		if r.Report == "" {
			continue
		}
		raw, err := readCapped(strings.TrimSuffix(r.Report, ".md") + ".json")
		if err != nil {
			continue
		}
		var rep struct {
			Findings []struct {
				ID, Title, Severity, Location string
			} `json:"findings"`
		}
		if json.Unmarshal(raw, &rep) != nil {
			continue
		}
		r.Findings = len(rep.Findings)
		for _, f := range rep.Findings {
			key := strings.Join(strings.Fields(strings.ToLower(f.Title)), " ")
			if key == "" {
				key = strings.ToLower(f.ID)
			}
			if x, ok := byKey[key]; ok {
				if !contains(x.Sources, r.Recipe) {
					x.Sources = append(x.Sources, r.Recipe)
				}
				if rank(f.Severity) < rank(x.Severity) {
					x.Severity = f.Severity
				}
				continue
			}
			byKey[key] = &Finding{ID: f.ID, Title: f.Title, Severity: f.Severity, Location: f.Location, Sources: []string{r.Recipe}}
			order = append(order, key)
		}
	}
	out := make([]Finding, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i].Severity) < rank(out[j].Severity) })
	return out
}

func rank(s string) int {
	if r, ok := sevRank[strings.ToLower(s)]; ok {
		return r
	}
	return 5
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

func readCapped(p string) ([]byte, error) {
	st, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > 8<<20 {
		return nil, errors.New("not a regular report under 8 MB")
	}
	return os.ReadFile(p)
}

// Write saves the combined report as report.json and report.md in dir.
func Write(dir string, c Combined) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "report.json"), append(b, '\n'), 0o600); err != nil {
		return "", err
	}
	var md strings.Builder
	fmt.Fprintf(&md, "# Series report: %s\n\n- Target: %s\n- Started: %s\n- Finished: %s\n\n## Findings (merged)\n\n", c.Series, c.Target, c.Started, c.Finished)
	if len(c.Findings) == 0 {
		md.WriteString("None.\n")
	} else {
		md.WriteString("| Severity | Finding | Recipes |\n| --- | --- | --- |\n")
		for _, f := range c.Findings {
			fmt.Fprintf(&md, "| %s | %s | %s |\n", mdCell(f.Severity), mdCell(f.Title), strings.Join(f.Sources, ", "))
		}
	}
	md.WriteString("\n## Per recipe\n\n| Recipe | Agent | Status | Findings | Report |\n| --- | --- | --- | --- | --- |\n")
	for _, r := range c.Recipes {
		status := r.Status
		if r.Reason != "" {
			status += " (" + r.Reason + ")"
		}
		fmt.Fprintf(&md, "| %s | %s | %s | %d | %s |\n", r.Recipe, r.Agent, status, r.Findings, r.Report)
	}
	p := filepath.Join(dir, "report.md")
	return p, os.WriteFile(p, []byte(md.String()), 0o600)
}

// mdCell cleans an agent-written string (control and escape sequences
// removed, one line) and escapes the table separator.
func mdCell(s string) string { return strings.ReplaceAll(sanitize.Line(s, 300), "|", "\\|") }
