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
		Agents:   []string{"claude", "codex"}, // devin is blocked by sbx
		Run: fake(map[string]string{
			"sbx version": "sbx 0.48.0",
			"docker info --format {{.ServerVersion}}":   "29.5.2",
			"sbx secret ls --service anthropic --quiet": "anthropic-key",
			"sbx secret ls --service openai --quiet":    "openai-oauth",
			"gh auth status --active":                   "Logged in",
			"sbx secret ls --service devin --quiet":     "devin",
			"docker buildx version":                     "github.com/docker/buildx v0.36.1",
			"sbx policy ls --json":                      `{"rules":[{"scope":"global","applies_to":"all","resource_type":"network","decision":"deny","resources":["**"],"status":"active"}]}`,
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
		if r.ID == "agent-claude" && (r.Level != Warn || r.Fix != "sbx secret set anthropic") {
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
	r := policyCheck(context.Background(), fake(map[string]string{"sbx policy ls --json": `{"rules":[{"scope":"global","applies_to":"all","resource_type":"filesystem:read","decision":"allow","resources":["**"]}]}`}))
	if r.Level != Warn || r.Fix != PolicyInitCommand || r.Detail != "not initialized" {
		t.Fatalf("not initialized: %+v", r)
	}
	r = policyCheck(context.Background(), fake(map[string]string{"sbx policy ls --json": `{"rules":[{"scope":"global","applies_to":"all","resource_type":"network","decision":"deny","resources":["**"],"status":"active"}]}`}))
	if r.Level != OK || r.Detail != "deny-all" {
		t.Fatalf("initialized: %+v", r)
	}
}
