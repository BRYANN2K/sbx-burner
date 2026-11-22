// Package sandboxes tracks the sandboxes burner kept after a run (--keep)
// and burns them. Only sandboxes burner itself recorded are listed or
// burned: lab-* names in ~/.burner/sandboxes.json that sbx still knows.
package sandboxes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Entry is one kept sandbox, recorded when its run ended.
type Entry struct {
	Name    string    `json:"name"`
	RunDir  string    `json:"run_dir"`
	Recipe  string    `json:"recipe"`
	Agent   string    `json:"agent"`
	Created time.Time `json:"created"`
}

// Kept is an entry joined with what sbx reports now.
type Kept struct {
	Entry
	State string `json:"state"` // sbx status: running, stopped, …
}

var nameRE = regexp.MustCompile(`^lab-[a-z0-9][a-z0-9-]{0,62}$`)

// ValidName reports whether name is a sandbox burner creates.
func ValidName(name string) bool { return nameRE.MatchString(name) }

func registry(home string) string { return filepath.Join(home, "sandboxes.json") }

// Load reads the registry; a missing file is an empty list.
func Load(home string) ([]Entry, error) {
	b, err := os.ReadFile(registry(home))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, errors.New("sandboxes.json is too large")
	}
	var out []Entry
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("sandboxes.json: %w", err)
	}
	valid := out[:0]
	for _, e := range out {
		if ValidName(e.Name) {
			valid = append(valid, e)
		}
	}
	return valid, nil
}

func save(home string, list []Entry) error {
	if err := os.MkdirAll(home, 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(list, "", "  ")
	return writeAtomic(registry(home), append(b, '\n'))
}

// writeAtomic writes through a unique temp file in the same folder (0600),
// then renames it over path.
func writeAtomic(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Add records a kept sandbox (replacing an entry with the same name).
func Add(home string, e Entry) error {
	if !ValidName(e.Name) {
		return fmt.Errorf("%q is not a burner sandbox name", e.Name)
	}
	list, err := Load(home)
	if err != nil {
		return err
	}
	out := []Entry{e}
	for _, x := range list {
		if x.Name != e.Name {
			out = append(out, x)
		}
	}
	return save(home, out)
}

// Remove forgets a sandbox.
func Remove(home, name string) error {
	list, err := Load(home)
	if err != nil {
		return err
	}
	out := []Entry{}
	for _, x := range list {
		if x.Name != name {
			out = append(out, x)
		}
	}
	return save(home, out)
}

// Lister returns the sandboxes sbx knows (name → status).
type Lister func(ctx context.Context) (map[string]string, error)

// Remover removes one sandbox in sbx.
type Remover func(ctx context.Context, name string) error

// SbxList runs `sbx ls --json`.
func SbxList(ctx context.Context) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sbx", "ls", "--json").Output()
	if err != nil {
		return nil, err
	}
	var rows []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, r := range rows {
		m[r.Name] = r.Status
	}
	return m, nil
}

// SbxRemove runs `sbx rm --force NAME`.
func SbxRemove(ctx context.Context, name string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sbx", "rm", "--force", "--", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sbx rm %s: %s", name, strings.TrimSpace(firstLine(string(out))))
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// List returns the kept sandboxes sbx still has, newest first. Entries sbx
// no longer knows are dropped from the registry.
func List(ctx context.Context, home string, ls Lister) ([]Kept, error) {
	list, err := Load(home)
	if err != nil {
		return nil, err
	}
	live, err := ls(ctx)
	if err != nil {
		return nil, err
	}
	var out []Kept
	stale := false
	for _, e := range list {
		st, ok := live[e.Name]
		if !ok {
			stale = true
			continue
		}
		out = append(out, Kept{Entry: e, State: st})
	}
	if stale {
		keep := make([]Entry, len(out))
		for i, k := range out {
			keep[i] = k.Entry
		}
		_ = save(home, keep)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out, nil
}

// Burn removes a kept sandbox burner recorded; anything else is refused.
func Burn(ctx context.Context, home, name string, rm Remover) error {
	if !ValidName(name) {
		return fmt.Errorf("%q is not a burner sandbox", name)
	}
	list, err := Load(home)
	if err != nil {
		return err
	}
	found := false
	for _, e := range list {
		found = found || e.Name == name
	}
	if !found {
		return fmt.Errorf("%s was not kept by burner", name)
	}
	if err := rm(ctx, name); err != nil {
		return err
	}
	return Remove(home, name)
}

// Age is a short human age: 5m, 3h, 2d.
func Age(created, now time.Time) string {
	d := now.Sub(created)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}
