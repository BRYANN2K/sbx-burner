package appdetect

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestNodeVite(t *testing.T) {
	d := t.TempDir()
	write(t, d, "package.json", `{"scripts":{"dev":"vite","start":"node server.js"},"devDependencies":{"vite":"5"}}`)
	write(t, d, "package-lock.json", "{}")
	a, ok := Detect(d)
	if !ok || a.Stack != "npm" || a.Install != "npm ci" || a.Start != "npm run dev" || a.Port != 5173 {
		t.Fatalf("got %+v", a)
	}
}

func TestNodePortFromScriptAndEnv(t *testing.T) {
	d := t.TempDir()
	write(t, d, "package.json", `{"scripts":{"start":"next start -p 4000"}}`)
	write(t, d, "pnpm-lock.yaml", "")
	a, _ := Detect(d)
	if a.Stack != "pnpm" || a.Start != "pnpm start" || a.Port != 4000 {
		t.Fatalf("got %+v", a)
	}
	write(t, d, ".env", "PORT=4100\n")
	if a, _ := Detect(d); a.Port != 4100 {
		t.Fatalf(".env PORT ignored: %+v", a)
	}
}

func TestPythonFastAPI(t *testing.T) {
	d := t.TempDir()
	write(t, d, "requirements.txt", "fastapi\nuvicorn\n")
	a, ok := Detect(d)
	if !ok || a.Stack != "python" || a.Port != 8000 || a.Hosts[0] != "pypi.org:443" {
		t.Fatalf("got %+v", a)
	}
}

func TestUnknown(t *testing.T) {
	if _, ok := Detect(t.TempDir()); ok {
		t.Fatal("empty dir detected as an app")
	}
}
