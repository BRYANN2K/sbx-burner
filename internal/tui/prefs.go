package tui

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/BRYANN2K/sbx-burner/internal/catalog"
)

// Prefs are the defaults chosen in setup (~/.burner/config.yaml): the
// flow starts on them, the user can still change each run.
type Prefs struct {
	Agent      string `yaml:"agent,omitempty"`
	Model      string `yaml:"model,omitempty"`
	Mode       string `yaml:"mode,omitempty"`       // acp | interactive | headless
	Permission string `yaml:"permission,omitempty"` // auto | ask
	Keep       bool   `yaml:"keep,omitempty"`
	RunsDir    string `yaml:"runs_dir,omitempty"`
	// CustomModels are model ids typed in "Other model…", per agent, so
	// they are offered again.
	CustomModels map[string][]string `yaml:"custom_models,omitempty"`
}

func prefsPath() string { return filepath.Join(catalog.Home(), "config.yaml") }

// LoadPrefs reads ~/.burner/config.yaml; ok is false when there is none
// (first launch).
func LoadPrefs() (Prefs, bool) {
	var p Prefs
	b, err := os.ReadFile(prefsPath())
	if err != nil || len(b) > 64<<10 {
		return p, false
	}
	if yaml.Unmarshal(b, &p) != nil {
		return Prefs{}, true
	}
	return p, true
}

// SavePrefs writes ~/.burner/config.yaml (0600) through a temp file.
func SavePrefs(p Prefs) error {
	home := catalog.Home()
	if home == "" {
		return errors.New("no home folder")
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return err
	}
	b, err := yaml.Marshal(p)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(home, ".config-*")
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
	return os.Rename(tmp, prefsPath())
}

// runsDir is the configured runs folder, ~ expanded.
func (p Prefs) runsDir() string {
	return expandHome(strings.TrimSpace(p.RunsDir))
}
