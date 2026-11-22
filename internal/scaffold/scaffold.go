// Package scaffold creates a user recipe from the catalog's template/.
package scaffold

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var nameRE = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// Categories a user recipe may use (same list as the runner, without apple).
var Categories = []string{"devsecops", "pentest", "malware", "detection", "hardening", "ir", "ai-security", "dev", "ci", "web", "cu"}

// New copies templateDir to destRoot/<category>/<name>, replacing the
// __NAME__ and __CATEGORY__ placeholders in file names and contents.
// It refuses to overwrite an existing recipe.
func New(templateDir, destRoot, category, name string) (string, error) {
	if !nameRE.MatchString(name) {
		return "", fmt.Errorf("name %q: use lowercase letters, digits and dashes", name)
	}
	if !contains(Categories, category) {
		return "", fmt.Errorf("category %q: one of %s", category, strings.Join(Categories, ", "))
	}
	dest := filepath.Join(destRoot, category, name)
	if _, err := os.Stat(dest); err == nil {
		return "", fmt.Errorf("%s already exists", dest)
	}
	replace := strings.NewReplacer("__NAME__", name, "__CATEGORY__", category)

	err := filepath.WalkDir(templateDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(templateDir, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dest, replace.Replace(rel))
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !d.Type().IsRegular() {
			return nil // no symlinks or devices from a template
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, []byte(replace.Replace(string(data))), info.Mode().Perm())
	})
	if err != nil {
		_ = os.RemoveAll(dest)
		return "", err
	}
	return dest, nil
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
