package engine

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Cancelling the context (Ctrl+C on burner) must interrupt the engine and
// let its teardown finish, not SIGKILL it.
func TestCancelInterruptsAndWaitsForCleanup(t *testing.T) {
	dir := t.TempDir()
	mark := filepath.Join(dir, "cleaned")
	fake := filepath.Join(dir, "python")
	script := "#!/bin/sh\ntrap 'sleep 0.5; echo done > \"" + mark + "\"; exit 130' INT\nwhile :; do sleep 0.05; done\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BURNER_PYTHON", fake)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(300 * time.Millisecond); cancel() }()
	start := time.Now()
	code, _ := ExecStreams(ctx, dir, []string{"run", "x"}, nil, io.Discard, io.Discard)
	if _, err := os.Stat(mark); err != nil {
		t.Fatalf("teardown did not run before exit (code %d after %s)", code, time.Since(start))
	}
}

func TestCleanupTimeoutStillKills(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "python")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\ntrap '' INT\nwhile :; do sleep 0.05; done\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BURNER_PYTHON", fake)
	old := CleanupTimeout
	CleanupTimeout = 500 * time.Millisecond
	defer func() { CleanupTimeout = old }()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	done := make(chan struct{})
	go func() { _, _ = ExecStreams(ctx, dir, nil, nil, io.Discard, io.Discard); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("an engine ignoring SIGINT was never killed")
	}
}

func TestCleanupTimeoutIsReported(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "python")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\ntrap '' INT\nwhile :; do sleep 0.05; done\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BURNER_PYTHON", fake)
	old := CleanupTimeout
	CleanupTimeout = 300 * time.Millisecond
	defer func() { CleanupTimeout = old }()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	if _, err := ExecStreams(ctx, dir, nil, nil, io.Discard, io.Discard); !errors.Is(err, ErrCleanupTimeout) {
		t.Fatalf("err = %v, want ErrCleanupTimeout", err)
	}
}

func TestSandboxNameMatchesTheRunner(t *testing.T) {
	cases := map[string]string{
		"20261122-015445-secrets-scan":               "lab-secrets-scan-015445",
		"20261122-015445-" + strings.Repeat("a", 60): "lab-" + strings.Repeat("a", 44) + "-015445",
		"junk": "",
	}
	for in, want := range cases {
		if got := SandboxName(in); got != want {
			t.Errorf("SandboxName(%q) = %q, want %q", in, got, want)
		}
	}
}
