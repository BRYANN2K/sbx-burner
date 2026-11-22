package doctor

import (
	"context"
	"errors"
	"github.com/BRYANN2K/sbx-burner/internal/engine"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fake(out map[string]string) Runner {
	return func(_ context.Context, name string, args ...string) (string, error) {
		key := name + " " + strings.Join(args, " ")
		v, ok := out[key]
		if !ok {
			return "", errors.New("not found: " + key)
		}
		return v, nil
	}
}

func found(string) (string, error) { return "/bin/x", nil }

func TestAllGood(t *testing.T) {
	res := Check(context.Background(), Options{
		LookPath: found,
		Agents:   []string{"claude", "codex"},
		Run: fake(map[string]string{
			"sbx version": "sbx 0.48.0",
			"docker info --format {{.ServerVersion}}":                      "29.5.2",
			"sbx secret ls --service anthropic --quiet":                    "anthropic-key",
			"sbx secret ls --service openai --quiet":                       "openai-oauth",
			"gh auth status --active":                                      "Logged in",
			"sbx secret ls --service devin --quiet":                        "devin",
			"docker buildx version":                                        "github.com/docker/buildx v0.36.1",
			"python3 -c import sys; print('%d.%d' % sys.version_info[:2])": "3.13",
			"sbx policy ls --json":                                         `{"rules":[{"scope":"global","applies_to":"all","resource_type":"network","decision":"deny","resources":["**"],"status":"active"}]}`,
		}),
	})
	if Worst(res) != OK || !AgentReady(res, "claude") || !AgentReady(res, "codex") {
		t.Fatalf("results: %+v", res)
	}
}

func TestMissingSbxIsFatalAndCredentialsUnknown(t *testing.T) {
	res := Check(context.Background(), Options{
		LookPath: func(n string) (string, error) {
			if n == "sbx" {
				return "", errors.New("missing")
			}
			return "/bin/" + n, nil
		},
		Run: fake(map[string]string{"docker info --format {{.ServerVersion}}": "29"}),
	})
	if Worst(res) != Fail || AgentReady(res, "claude") {
		t.Fatalf("results: %+v", res)
	}
	for _, r := range res {
		if r.ID == "sbx" && r.Fix == "" {
			t.Fatal("sbx failure must say how to fix it")
		}
	}
}

func TestEmptySecretListIsAWarningWithFix(t *testing.T) {
	res := Check(context.Background(), Options{
		LookPath: found,
		Agents:   []string{"claude"},
		Run: fake(map[string]string{
			"sbx version": "sbx 0.48.0",
			"docker info --format {{.ServerVersion}}":   "29",
			"sbx secret ls --service anthropic --quiet": "",
		}),
	})
	for _, r := range res {
		if r.ID == "agent-claude" && (r.Level != Warn || !strings.HasPrefix(r.Fix, "sbx run claude")) {
			t.Fatalf("got %+v", r)
		}
	}
}

func TestNeverEchoesTokens(t *testing.T) {
	planted := []string{"sk-ant-api03-PLANTED", "ghp_PLANTEDPLANTEDPLANTED"}
	run := func(_ context.Context, name string, args ...string) (string, error) {
		key := name + " " + strings.Join(args, " ")
		out := "token " + planted[0] + " " + planted[1]
		if strings.HasPrefix(key, "sbx secret") {
			return out, errors.New("boom")
		}
		return out, nil
	}
	res := Check(context.Background(), Options{LookPath: found, Run: run})
	for _, r := range res {
		for _, p := range planted {
			if strings.Contains(r.Detail+r.Fix+r.Title, p) {
				t.Fatalf("token echoed in %+v", r)
			}
		}
	}
}

func TestRegistryLoginsNamesOnly(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".docker"), 0o700)
	os.WriteFile(filepath.Join(home, ".docker", "config.json"), []byte(`{"auths":{"ghcr.io":{"auth":"c2VjcmV0"}},"credHelpers":{"123.dkr.ecr.aws":"ecr-login"}}`), 0o600)
	got := strings.Join(RegistryLogins(home), ",")
	if got != "123.dkr.ecr.aws,ghcr.io" || strings.Contains(got, "c2VjcmV0") {
		t.Fatalf("got %q", got)
	}
}

func TestAppleContainerCountsAsRuntime(t *testing.T) {
	res := Check(context.Background(), Options{
		LookPath: found,
		Agents:   []string{"claude"},
		Run: fake(map[string]string{
			"sbx version":                               "sbx 0.48.0",
			"container system status":                   "running",
			"sbx secret ls --service anthropic --quiet": "k",
			"gh auth status --active":                   "ok",
		}),
	})
	for _, r := range res {
		if r.ID == "runtime" && (r.Level != OK || r.Detail != "Apple container") {
			t.Fatalf("got %+v", r)
		}
	}
}

func TestApprovalResults(t *testing.T) {
	rows := []engine.Approval{
		{Agent: "codex", Kit: "kits/agent-codex", Approved: true},
		{Agent: "claude", Kit: "kits/agent-claude", Missing: map[string][]string{"anthropic": {"api.anthropic.com"}}},
		{Agent: "cursor", Error: "bindings.cursor is not a mapping"},
	}
	res := ApprovalResults(rows)
	if len(res) != 3 || res[0].Level != OK || res[1].Fix != "burner approve --agent claude" || !strings.Contains(res[1].Detail, "api.anthropic.com") || res[2].Level != Warn {
		t.Fatalf("results %+v", res)
	}
	if got := strings.Join(ApprovalsNeeded(res), ","); got != "claude,cursor" {
		t.Fatalf("needed %s", got)
	}
}

func TestPolicyCheck(t *testing.T) {
	_, r := policyCheck(context.Background(), fake(map[string]string{"sbx policy ls --json": `{"rules":[{"scope":"global","applies_to":"all","resource_type":"filesystem:read","decision":"allow","resources":["**"]}]}`}), machineEnv{goos: "darwin"})
	if r.Level != Warn || r.Fix != PolicyInitCommand || r.Detail != "not initialized" {
		t.Fatalf("not initialized: %+v", r)
	}
	_, r = policyCheck(context.Background(), fake(map[string]string{"sbx policy ls --json": `{"rules":[{"scope":"global","applies_to":"all","resource_type":"network","decision":"deny","resources":["**"],"status":"active"}]}`}), machineEnv{goos: "darwin"})
	if r.Level != OK || r.Detail != "deny-all" {
		t.Fatalf("initialized: %+v", r)
	}
}

func none(string) (string, error) { return "", errors.New("missing") }

func failAll(_ context.Context, name string, args ...string) (string, error) {
	return "", errors.New("not run")
}

func byID(res []Result, id string) Result {
	for _, r := range res {
		if r.ID == id {
			return r
		}
	}
	return Result{}
}

// A Mac with nothing installed: every machine line is red, in install
// order, and only Homebrew's own installer can run before brew exists.
func TestNothingInstalledMac(t *testing.T) {
	res := Check(context.Background(), Options{LookPath: none, Run: failAll, GOOS: "darwin", Exists: func(string) bool { return false }})
	var ids []string
	for _, r := range res {
		if !strings.HasPrefix(r.ID, "agent-") && r.ID != "registry-login" {
			ids = append(ids, r.ID)
		}
	}
	if got := strings.Join(ids, ","); got != "brew,sbx,runtime,buildx,git,python,git-login" {
		t.Fatalf("order %s", got)
	}
	brew := byID(res, "brew")
	if brew.Level != Fail || len(brew.Actions) != 1 || strings.Join(brew.Actions[0].Argv, " ") != "/bin/bash -c "+brewInstallScript {
		t.Fatalf("brew %+v", brew)
	}
	for _, id := range []string{"sbx", "buildx", "git", "python", "git-login"} {
		r := byID(res, id)
		if len(r.Actions) == 0 || r.Actions[0].Argv != nil || r.Actions[0].Note != "needs Homebrew first" {
			t.Fatalf("%s before brew: %+v", id, r.Actions)
		}
	}
	rt := byID(res, "runtime")
	if len(rt.Actions) != 3 || rt.Actions[0].Label != "colima" || rt.Actions[1].Label != "Docker Desktop" || rt.Actions[2].Label != "Apple container" {
		t.Fatalf("runtime %+v", rt.Actions)
	}
}

func TestMacActionsWithBrew(t *testing.T) {
	exists := func(p string) bool { return p == "/opt/homebrew/bin/brew" }
	res := Check(context.Background(), Options{LookPath: none, Run: failAll, GOOS: "darwin", Exists: exists})
	argv := func(id string, i int) string { return strings.Join(byID(res, id).Actions[i].Argv, " ") }
	if byID(res, "brew").Level != OK {
		t.Fatal("brew at /opt/homebrew counts as installed")
	}
	want := map[string]string{
		"sbx":    "/opt/homebrew/bin/brew install docker/tap/sbx",
		"git":    "/opt/homebrew/bin/brew install git",
		"python": "/opt/homebrew/bin/brew install python@3.13",
	}
	for id, w := range want {
		if got := argv(id, 0); got != w {
			t.Fatalf("%s: %q", id, got)
		}
	}
	if got := argv("runtime", 0); got != `/bin/sh -c brew='/opt/homebrew/bin/brew'; "$brew" install colima docker && colima start` {
		t.Fatalf("colima: %q", got)
	}
	bx := argv("buildx", 0)
	for _, part := range []string{`"$brew" install docker docker-buildx`, `mkdir -p "$HOME/.docker/cli-plugins"`, `ln -sfn "$("$brew" --prefix)/bin/docker-buildx" "$HOME/.docker/cli-plugins/docker-buildx"`, "docker buildx version"} {
		if !strings.Contains(bx, part) {
			t.Fatalf("buildx %q lacks %q", bx, part)
		}
	}
	if got := argv("git-login", 0); got != `/bin/sh -c brew='/opt/homebrew/bin/brew'; "$brew" install gh && gh auth login` {
		t.Fatalf("gh: %q", got)
	}
}

func TestRuntimeInstalledButStopped(t *testing.T) {
	look := func(n string) (string, error) {
		if n == "colima" || n == "docker" {
			return "/opt/homebrew/bin/" + n, nil
		}
		return "", errors.New("missing")
	}
	res := Check(context.Background(), Options{LookPath: look, Run: failAll, GOOS: "darwin", Exists: func(string) bool { return false }})
	rt := byID(res, "runtime")
	if rt.Detail != "installed, not running" || len(rt.Actions) != 1 || strings.Join(rt.Actions[0].Argv, " ") != "colima start" {
		t.Fatalf("runtime %+v", rt)
	}
}

func TestShimsWithoutCommandLineToolsAreMissing(t *testing.T) {
	look := func(n string) (string, error) {
		if n == "git" || n == "python3" {
			return "/usr/bin/" + n, nil
		}
		return "", errors.New("missing")
	}
	ran := false
	run := func(_ context.Context, name string, args ...string) (string, error) {
		if name == "python3" {
			ran = true
		}
		return "", errors.New("no")
	}
	res := Check(context.Background(), Options{LookPath: look, Run: run, GOOS: "darwin", Exists: func(string) bool { return false }})
	if byID(res, "git").Level != Fail || byID(res, "python").Level != Fail || ran {
		t.Fatal("the /usr/bin shims must not run without the Command Line Tools")
	}
}

func TestOldPythonFails(t *testing.T) {
	res := Check(context.Background(), Options{LookPath: found, GOOS: "darwin", Exists: func(string) bool { return true },
		Run: fake(map[string]string{"python3 -c import sys; print('%d.%d' % sys.version_info[:2])": "3.9"})})
	if r := byID(res, "python"); r.Level != Fail || r.Detail != "3.9 (3.11 or newer needed)" {
		t.Fatalf("python %+v", r)
	}
}

func TestSignInAndPolicyLines(t *testing.T) {
	res := Check(context.Background(), Options{LookPath: found, GOOS: "darwin", Exists: func(string) bool { return true },
		Run: func(_ context.Context, name string, args ...string) (string, error) {
			k := name + " " + strings.Join(args, " ")
			switch k {
			case "sbx version":
				return "sbx version v0.54.0", nil
			case "sbx policy ls --json":
				return "not signed in: run sbx login", errors.New("exit 1")
			}
			return "", errors.New("no")
		}})
	login, policy := byID(res, "sbx-login"), byID(res, "policy")
	if login.Level != Warn || strings.Join(login.Actions[0].Argv, " ") != "sbx login" || len(policy.Actions) != 0 {
		t.Fatalf("login %+v policy %+v", login, policy)
	}
	_, p := policyCheck(context.Background(), fake(map[string]string{"sbx policy ls --json": `{"rules":[]}`}), machineEnv{goos: "darwin"})
	if strings.Join(p.Actions[0].Argv, " ") != PolicyInitCommand || !strings.Contains(p.Actions[0].Note, "every sbx sandbox on this Mac") {
		t.Fatalf("policy %+v", p)
	}
}

func TestLinuxUsesOfficialPathsOrDocs(t *testing.T) {
	look := func(n string) (string, error) {
		if n == "apt-get" {
			return "/usr/bin/apt-get", nil
		}
		return "", errors.New("missing")
	}
	read := func(string) ([]byte, error) { return []byte("NAME=Ubuntu\nID=ubuntu\n"), nil }
	res := Check(context.Background(), Options{LookPath: look, Run: failAll, GOOS: "linux", Exists: func(string) bool { return false }, ReadFile: read})
	if byID(res, "brew").ID != "" {
		t.Fatal("no Homebrew line on Linux")
	}
	if got := strings.Join(byID(res, "sbx").Actions[0].Argv, " "); got != "/bin/sh -c "+sbxAptInstall {
		t.Fatalf("sbx %q", got)
	}
	if byID(res, "runtime").Actions[0].URL != engineDocs || byID(res, "git-login").Actions[0].URL != ghLinuxDocs {
		t.Fatal("no known command: show the doc page")
	}
	if got := strings.Join(byID(res, "git").Actions[0].Argv, " "); got != "sudo apt-get install -y git" {
		t.Fatalf("git %q", got)
	}
	read2 := func(string) ([]byte, error) { return []byte("ID=fedora\n"), nil }
	res = Check(context.Background(), Options{LookPath: none, Run: failAll, GOOS: "linux", Exists: func(string) bool { return false }, ReadFile: read2})
	if a := byID(res, "sbx").Actions[0]; a.Argv != nil || a.URL != sbxDocs {
		t.Fatalf("sbx on fedora %+v", a)
	}
}
