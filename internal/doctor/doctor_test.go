package doctor

import (
	"context"
	"errors"
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
		Run: fake(map[string]string{
			"sbx version": "sbx 0.48.0",
			"docker info --format {{.ServerVersion}}":   "29.5.2",
			"sbx secret ls --service anthropic --quiet": "anthropic-key",
			"sbx secret ls --service openai --quiet":    "openai-oauth",
			"gh auth status --active":                   "Logged in",
			"sbx secret ls --service devin --quiet":     "devin",
			"docker buildx version":                     "github.com/docker/buildx v0.36.1",
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
