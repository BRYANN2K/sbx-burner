package engine

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// A cancelled interruptible run gets SIGINT (so the runner can still
// destroy the sandbox), not SIGKILL.
func TestExecInterruptibleSendsSIGINT(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "interrupted")
	script := filepath.Join(dir, "fake-python")
	body := "#!/bin/sh\ntrap 'echo teardown > " + marker + "; exit 7' INT\necho started\nwhile :; do sleep 0.05; done\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BURNER_PYTHON", script)
	ctx, cancel := context.WithCancel(context.Background())
	out := &syncBuf{}
	done := make(chan int, 1)
	go func() {
		code, _ := ExecInterruptible(ctx, dir, []string{"run", "x"}, out, out)
		done <- code
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !out.has("started") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case code := <-done:
		if code != 7 {
			t.Fatalf("exit %d, want 7 (the INT trap)", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("engine did not stop")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("the engine never saw SIGINT")
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) has(sub string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Contains(s.b.Bytes(), []byte(sub))
}
