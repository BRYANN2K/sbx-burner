// Package appdetect guesses how to install and start a local project, so
// the menu can propose it and the user only confirms. The runner does the
// real work inside the sandbox; this is the host-side preview.
package appdetect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// App is a detected project.
type App struct {
	Stack   string   `json:"stack"`   // npm, pnpm, yarn, python, go, rails, php, rust
	Install string   `json:"install"` // command, empty when none
	Start   string   `json:"start"`
	Port    int      `json:"port"`
	Hosts   []string `json:"install_hosts"` // registry hosts, install-only
}

var portFlag = regexp.MustCompile(`(?:--port[ =]|-p\s+|PORT=|:)(\d{2,5})\b`)

// Detect inspects dir. ok is false when no known stack is found.
func Detect(dir string) (App, bool) {
	has := func(name string) bool {
		st, err := os.Lstat(filepath.Join(dir, name))
		return err == nil && st.Mode().IsRegular()
	}
	switch {
	case has("package.json"):
		return node(dir, has), true
	case has("pyproject.toml") || has("requirements.txt"):
		return python(dir, has), true
	case has("go.mod"):
		return App{Stack: "go", Install: "go mod download", Start: "go run .", Port: envPort(dir, 8080),
			Hosts: []string{"proxy.golang.org:443", "sum.golang.org:443"}}, true
	case has("Gemfile"):
		return App{Stack: "rails", Install: "bundle install", Start: "bin/rails server -b 0.0.0.0", Port: envPort(dir, 3000),
			Hosts: []string{"rubygems.org:443", "index.rubygems.org:443"}}, true
	case has("composer.json"):
		return App{Stack: "php", Install: "composer install", Start: "php -S 0.0.0.0:8000 -t public", Port: envPort(dir, 8000),
			Hosts: []string{"repo.packagist.org:443"}}, true
	case has("Cargo.toml"):
		return App{Stack: "rust", Install: "cargo fetch", Start: "cargo run", Port: envPort(dir, 8080),
			Hosts: []string{"index.crates.io:443", "static.crates.io:443"}}, true
	}
	return App{}, false
}

func node(dir string, has func(string) bool) App {
	a := App{Stack: "npm", Install: "npm ci", Hosts: []string{"registry.npmjs.org:443"}}
	switch {
	case has("pnpm-lock.yaml"):
		a.Stack, a.Install = "pnpm", "pnpm install --frozen-lockfile"
	case has("yarn.lock"):
		a.Stack, a.Install = "yarn", "yarn install --frozen-lockfile"
		a.Hosts = append(a.Hosts, "registry.yarnpkg.com:443")
	case !has("package-lock.json"):
		a.Install = "npm install"
	}
	var pkg struct {
		Scripts      map[string]string `json:"scripts"`
		Dependencies map[string]string `json:"dependencies"`
		DevDeps      map[string]string `json:"devDependencies"`
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "package.json"))
	_ = json.Unmarshal(raw, &pkg)
	run := map[string]string{"npm": "npm run ", "pnpm": "pnpm ", "yarn": "yarn "}[a.Stack]
	script := ""
	for _, name := range []string{"dev", "start", "serve"} {
		if s, ok := pkg.Scripts[name]; ok {
			script = s
			a.Start = run + name
			break
		}
	}
	if a.Start == "" {
		a.Start = "node index.js"
	}
	dep := func(n string) bool { _, a := pkg.Dependencies[n]; _, b := pkg.DevDeps[n]; return a || b }
	def := 3000
	switch {
	case dep("vite"):
		def = 5173
	case dep("@angular/core"):
		def = 4200
	}
	if p := firstPort(script); p != 0 {
		def = p
	}
	a.Port = envPort(dir, def)
	return a
}

func python(dir string, has func(string) bool) App {
	a := App{Stack: "python", Hosts: []string{"pypi.org:443", "files.pythonhosted.org:443"}, Port: envPort(dir, 8000)}
	if has("requirements.txt") {
		a.Install = "pip install -r requirements.txt"
	} else {
		a.Install = "pip install ."
	}
	text := ""
	for _, f := range []string{"requirements.txt", "pyproject.toml"} {
		b, _ := os.ReadFile(filepath.Join(dir, f))
		text += strings.ToLower(string(b))
	}
	switch {
	case has("manage.py"):
		a.Start = "python manage.py runserver 0.0.0.0:8000"
	case strings.Contains(text, "fastapi") || strings.Contains(text, "uvicorn"):
		a.Start = "uvicorn main:app --host 0.0.0.0 --port 8000"
	case strings.Contains(text, "flask"):
		a.Start, a.Port = "flask run --host 0.0.0.0", envPort(dir, 5000)
	default:
		a.Start = "python app.py"
	}
	return a
}

// envPort reads PORT from .env, else returns def.
func envPort(dir string, def int) int {
	path := filepath.Join(dir, ".env")
	if st, err := os.Lstat(path); err != nil || !st.Mode().IsRegular() {
		return def
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return def
	}
	for _, line := range strings.Split(string(raw), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.TrimSpace(k) == "PORT" {
			if p, err := strconv.Atoi(strings.Trim(strings.TrimSpace(v), `"'`)); err == nil && p > 0 && p < 65536 {
				return p
			}
		}
	}
	return def
}

func firstPort(script string) int {
	m := portFlag.FindStringSubmatch(script)
	if m == nil {
		return 0
	}
	p, _ := strconv.Atoi(m[1])
	if p <= 0 || p >= 65536 {
		return 0
	}
	return p
}
