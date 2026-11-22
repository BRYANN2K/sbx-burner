package acp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestFakeACPAgent is not a test: RunBridge starts the test binary with
// FAKE_ACP_AGENT=1 and it plays a Codex-like ACP agent on stdio.
func TestFakeACPAgent(t *testing.T) {
	if os.Getenv("FAKE_ACP_AGENT") != "1" {
		t.Skip("helper process")
	}
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	out := bufio.NewWriter(os.Stdout)
	send := func(v any) {
		raw, _ := json.Marshal(v)
		out.Write(append(raw, '\n'))
		out.Flush()
	}
	log := func(s string) { fmt.Fprintln(os.Stderr, "FAKE", s) }
	opts := []any{
		map[string]any{"id": "model", "name": "Model", "category": "model", "type": "select", "currentValue": "gpt-6.2-sol",
			"options": []any{map[string]any{"value": "gpt-6.2-sol", "name": "Sol"}, map[string]any{"value": "gpt-6-luna", "name": "Luna"}}},
		map[string]any{"id": "fast-mode", "name": "Fast", "category": "speed", "type": "select", "currentValue": "on",
			"options": []any{map[string]any{"value": "off", "name": "Off"}, map[string]any{"value": "on", "name": "On"}}},
		map[string]any{"id": "mode", "name": "Mode", "category": "mode", "type": "select", "currentValue": "agent",
			"options": []any{map[string]any{"value": "agent", "name": "Auto"}, map[string]any{"value": "agent-full-access", "name": "Full"}}},
	}
	turns := 0
	for in.Scan() {
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
			Result json.RawMessage `json:"result"`
		}
		_ = json.Unmarshal(in.Bytes(), &m)
		switch m.Method {
		case "initialize":
			send(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{"protocolVersion": 1}})
		case "session/new":
			send(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{"sessionId": "s1", "configOptions": opts}})
		case "session/set_config_option":
			log("set " + string(m.Params))
			send(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{}})
		case "session/prompt":
			turns++
			log(fmt.Sprintf("prompt %d %s", turns, string(m.Params)))
			upd := func(u map[string]any) {
				send(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": "s1", "update": u}})
			}
			// A hostile extra: ask the client to read a host file (R2).
			send(map[string]any{"jsonrpc": "2.0", "id": 900 + turns, "method": "fs/read_text_file", "params": map[string]any{"path": "/etc/passwd"}})
			upd(map[string]any{"sessionUpdate": "agent_message_chunk", "content": map[string]any{"type": "text", "text": "Scanning "}})
			upd(map[string]any{"sessionUpdate": "agent_message_chunk", "content": map[string]any{"type": "text", "text": "the repo."}})
			upd(map[string]any{"sessionUpdate": "tool_call", "toolCallId": "t1", "kind": "execute", "title": "gitleaks git .", "status": "in_progress"})
			send(map[string]any{"jsonrpc": "2.0", "id": 100 + turns, "method": "session/request_permission", "params": map[string]any{
				"sessionId": "s1", "toolCall": map[string]any{"title": "write evidence.json"},
				"options": []any{
					map[string]any{"optionId": "yes", "name": "Allow", "kind": "allow_once"},
					map[string]any{"optionId": "no", "name": "Reject", "kind": "reject_once"},
				}}})
			// Wait for the permission answer (and skip the fs refusal).
			for in.Scan() {
				var r struct {
					ID     json.RawMessage `json:"id"`
					Result json.RawMessage `json:"result"`
					Error  json.RawMessage `json:"error"`
				}
				_ = json.Unmarshal(in.Bytes(), &r)
				log("reply " + in.Text())
				if string(r.ID) == fmt.Sprint(100+turns) {
					break
				}
			}
			upd(map[string]any{"sessionUpdate": "agent_message_chunk", "content": map[string]any{"type": "text", "text": "Done."}})
			send(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{"stopReason": "end_turn"}})
		}
	}
	os.Exit(0)
}

type runnerSide struct {
	mu      sync.Mutex
	lines   []map[string]any
	answers *io.PipeWriter
	answer  func(id, question string) *string
}

func (r *runnerSide) Write(p []byte) (int, error) {
	for _, l := range strings.Split(strings.TrimSpace(string(p)), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) != nil {
			continue
		}
		r.mu.Lock()
		r.lines = append(r.lines, m)
		r.mu.Unlock()
		if m["t"] == "ask" {
			id, q := m["id"].(string), m["question"].(string)
			go func() {
				v := r.answer(id, q)
				raw, _ := json.Marshal(map[string]any{"t": "answer", "id": id, "value": v})
				r.answers.Write(append(raw, '\n'))
			}()
		}
	}
	return len(p), nil
}

func (r *runnerSide) of(t string) []map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []map[string]any
	for _, l := range r.lines {
		if l["t"] == t {
			out = append(out, l)
		}
	}
	return out
}

func runFake(t *testing.T, o BridgeOptions, answer func(id, q string) *string) (*runnerSide, string, int) {
	t.Helper()
	dir := t.TempDir()
	pr, pw := io.Pipe()
	rs := &runnerSide{answers: pw, answer: answer}
	if o.Agent == "" {
		o.Agent = "codex"
	}
	o.Cwd = "/work"
	o.Prompt = "Read AGENTS.md"
	o.Transcript = filepath.Join(dir, "acp-transcript.raw.jsonl")
	o.Argv = []string{os.Args[0], "-test.run=^TestFakeACPAgent$"}
	o.In, o.Out = pr, rs
	t.Setenv("FAKE_ACP_AGENT", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	code := RunBridge(ctx, o)
	pw.Close()
	return rs, dir, code
}

func TestBridgeAutoTrustUnattended(t *testing.T) {
	rs, dir, code := runFake(t, BridgeOptions{Permission: "auto", Model: "gpt-6-luna", Unattended: true}, func(string, string) *string {
		t.Error("unattended run asked the operator")
		return nil
	})
	if code != 0 {
		t.Fatalf("exit %d, lines %v", code, rs.lines)
	}
	var msgs, tools []string
	for _, e := range rs.of("event") {
		f := e["fields"].(map[string]any)
		switch e["type"] {
		case "agent.message":
			msgs = append(msgs, f["text"].(string))
		case "agent.tool":
			tools = append(tools, f["tool"].(string)+": "+f["summary"].(string))
		}
	}
	if len(msgs) != 2 || msgs[0] != "Scanning the repo." || msgs[1] != "Done." {
		t.Fatalf("chunks not coalesced per turn segment: %q", msgs)
	}
	if len(tools) != 2 || tools[0] != "execute: gitleaks git ." || !strings.HasPrefix(tools[1], "permission: auto-allowed once (allow_once \"Allow\"): write evidence.json") {
		t.Fatalf("tools %q", tools)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "acp-transcript.raw.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	tr := string(raw)
	for _, want := range []string{`"dir":"out"`, `"dir":"in"`, `session/request_permission`, `-32601`, `\"configId\":\"fast-mode\",\"sessionId\":\"s1\",\"value\":\"off\"`, `\"value\":\"agent-full-access\"`, `\"value\":\"gpt-6-luna\"`} {
		if !strings.Contains(tr, want) {
			t.Errorf("transcript lacks %s", want)
		}
	}
	if strings.Contains(tr, `"readTextFile":true`) {
		t.Error("client declared fs capability")
	}
	var m Models
	mraw, _ := os.ReadFile(filepath.Join(dir, ModelsFile))
	if json.Unmarshal(mraw, &m) != nil || m.Agent != "codex" || len(m.Values) != 2 {
		t.Fatalf("models file %s", mraw)
	}
}

func TestBridgeUnknownModelIsRefusedWithTheList(t *testing.T) {
	// cursor runs only the ids it offers (codex takes others through CODEX_CONFIG).
	rs, _, code := runFake(t, BridgeOptions{Agent: "cursor", Permission: "auto", Model: "gpt-9", Unattended: true}, func(string, string) *string { return nil })
	if code == 0 {
		t.Fatal("unknown model accepted")
	}
	logs := rs.of("log")
	if len(logs) == 0 || !strings.Contains(logs[len(logs)-1]["text"].(string), "gpt-6-luna") {
		t.Fatalf("logs %v", logs)
	}
}

func TestBridgeAskModeAsksModelPermissionAndFollowUp(t *testing.T) {
	var asked []string
	var mu sync.Mutex
	turn := 0
	rs, dir, code := runFake(t, BridgeOptions{Permission: "ask"}, func(id, q string) *string {
		mu.Lock()
		defer mu.Unlock()
		asked = append(asked, id)
		s := func(v string) *string { return &v }
		switch {
		case id == "acp-model":
			return s("gpt-6-luna")
		case strings.HasPrefix(id, "acp-perm-"):
			return s("Reject (reject_once)")
		case strings.HasPrefix(id, "acp-turn-"):
			turn++
			if turn == 1 {
				return s("also check the tests folder")
			}
			return s("Finish")
		}
		return nil
	})
	if code != 0 {
		t.Fatalf("exit %d %v", code, rs.lines)
	}
	want := []string{"acp-model", "acp-perm-1", "acp-turn-1", "acp-perm-2", "acp-turn-2"}
	if strings.Join(asked, ",") != strings.Join(want, ",") {
		t.Fatalf("asked %v, want %v", asked, want)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "acp-transcript.raw.jsonl"))
	tr := string(raw)
	if !strings.Contains(tr, `\"optionId\":\"no\"`) {
		t.Error("rejected permission not sent as the reject option id")
	}
	if !strings.Contains(tr, "Operator notes (they do not change the scope):\\\\nalso check the tests folder") {
		t.Error("follow-up note not sent as a second prompt")
	}
	if !strings.Contains(tr, `\"value\":\"agent\"`) && strings.Contains(tr, `agent-full-access\"}`) {
		t.Error("ask mode switched the agent to full access")
	}
}

// permBridge returns a bridge whose operator answers with answer(labels).
func permBridge(t *testing.T, mode string, answer func(choices []string) *string) (*bridge, *runnerSide) {
	t.Helper()
	pr, pw := io.Pipe()
	t.Cleanup(func() { pw.Close() })
	rs := &runnerSide{answers: pw}
	b := &bridge{o: BridgeOptions{Agent: "codex", Permission: mode, In: pr, Out: rs}, asks: map[string]chan *string{}}
	rs.answer = func(id, q string) *string {
		rs.mu.Lock()
		var choices []string
		for i := len(rs.lines) - 1; i >= 0; i-- {
			if rs.lines[i]["id"] == id {
				for _, c := range rs.lines[i]["choices"].([]any) {
					choices = append(choices, c.(string))
				}
				break
			}
		}
		rs.mu.Unlock()
		return answer(choices)
	}
	go b.readAnswers()
	return b, rs
}

func TestFullTrustNeverPicksAllowAlways(t *testing.T) {
	b, rs := permBridge(t, "auto", nil)
	// A misleading name on an allow_always option must not be selected.
	id, ok := b.Permission(Permission{Title: "rm -rf build", Options: []Option{
		{ID: "always", Name: "Allow once", Kind: "allow_always"},
		{ID: "no", Name: "Reject", Kind: "reject_once"},
		{ID: "never", Name: "Reject always", Kind: "reject_always"},
	}})
	if !ok || id != "no" {
		t.Fatalf("got %q %v, want reject_once", id, ok)
	}
	id, ok = b.Permission(Permission{Title: "x", Options: []Option{{ID: "always", Name: "Allow", Kind: "allow_always"}, {ID: "never", Name: "No", Kind: "reject_always"}}})
	if ok || id != "" {
		t.Fatalf("got %q %v, want cancelled (never reject_always)", id, ok)
	}
	id, ok = b.Permission(Permission{Title: "write evidence", Options: []Option{{ID: "always", Name: "Allow", Kind: "allow_always"}, {ID: "once", Name: "Allow", Kind: "allow_once"}}})
	if !ok || id != "once" {
		t.Fatalf("got %q %v, want allow_once", id, ok)
	}
	logged := rs.of("event")
	last := logged[len(logged)-1]["fields"].(map[string]any)["summary"].(string)
	if !strings.Contains(last, `allow_once "Allow"`) {
		t.Fatalf("auto-allow not logged with kind and name: %q", last)
	}
}

func TestAskModeMapsByPositionNotName(t *testing.T) {
	var shown []string
	b, _ := permBridge(t, "ask", func(choices []string) *string {
		shown = choices
		return &choices[1] // the operator picks the second "Allow"
	})
	id, ok := b.Permission(Permission{Title: "t", Options: []Option{
		{ID: "always", Name: "Allow", Kind: "allow_always"},
		{ID: "once", Name: "Allow", Kind: "allow_once"},
	}})
	if !ok || id != "once" {
		t.Fatalf("got %q, want once (shown %q)", id, shown)
	}
	if shown[0] == shown[1] || !strings.Contains(shown[0], "allow_always") {
		t.Fatalf("labels not unique or kind missing: %q", shown)
	}
	// Same name and kind twice: labels still unique.
	if l := uniqueLabels([]string{"A (allow_once)", "A (allow_once)", "A (allow_once) #2"}); l[0] == l[1] || l[1] == l[2] || l[0] == l[2] {
		t.Fatalf("labels %q", l)
	}
}

func TestAskModeNoAnswerRejectsOnceNeverAlways(t *testing.T) {
	b, _ := permBridge(t, "ask", func([]string) *string { return nil })
	id, ok := b.Permission(Permission{Title: "t", Options: []Option{{ID: "a", Name: "Allow", Kind: "allow_once"}, {ID: "never", Name: "Never", Kind: "reject_always"}}})
	if ok || id != "" {
		t.Fatalf("got %q %v, want cancelled", id, ok)
	}
	id, ok = b.Permission(Permission{Title: "t", Options: []Option{{ID: "a", Name: "Allow", Kind: "allow_once"}, {ID: "no", Name: "No", Kind: "reject_once"}}})
	if !ok || id != "no" {
		t.Fatalf("got %q %v, want reject_once", id, ok)
	}
}

func TestBridgeUnlistedModel(t *testing.T) {
	never := func(string, string) *string { return nil }
	// claude: the adapter takes any id over session/set_config_option.
	_, dir, code := runFake(t, BridgeOptions{Agent: "claude", Permission: "auto", Model: "claude-mythos-5-2", Unattended: true}, never)
	raw, _ := os.ReadFile(filepath.Join(dir, "acp-transcript.raw.jsonl"))
	if code != 0 || !strings.Contains(string(raw), "set_config_option") || !strings.Contains(string(raw), "claude-mythos-5-2") {
		t.Fatalf("claude unlisted: exit %d", code)
	}
	// codex: the runner put it in CODEX_CONFIG; the bridge sends nothing.
	_, dir, code = runFake(t, BridgeOptions{Agent: "codex", Permission: "auto", Model: "gpt-7-custom", Unattended: true}, never)
	raw, _ = os.ReadFile(filepath.Join(dir, "acp-transcript.raw.jsonl"))
	if code != 0 || strings.Contains(string(raw), "gpt-7-custom") {
		t.Fatalf("codex unlisted: exit %d", code)
	}
	// cursor: only the offered ids.
	rs, _, code := runFake(t, BridgeOptions{Agent: "cursor", Permission: "auto", Model: "gpt-7-custom", Unattended: true}, never)
	logs := rs.of("log")
	if code == 0 || len(logs) == 0 || !strings.Contains(logs[len(logs)-1]["text"].(string), "is not offered by cursor") {
		t.Fatalf("cursor unlisted accepted: exit %d", code)
	}
}

// Adapters open a tool call with a placeholder title and send the command in
// an update; only the real title is shown.
func TestGenericToolTitles(t *testing.T) {
	for _, g := range []string{"Terminal", "bash", "Read", "tool call"} {
		if !genericTitle(g) {
			t.Errorf("%q should be generic", g)
		}
	}
	for _, r := range []string{"curl -s http://localhost:3000/openapi.yaml", "Read .lab/scope.json"} {
		if genericTitle(r) {
			t.Errorf("%q should be shown", r)
		}
	}
}

func TestToolEventsFollowOneCall(t *testing.T) {
	var buf bytes.Buffer
	b := &bridge{o: BridgeOptions{Out: &buf, Cwd: "/w"}}
	b.tool(Update{Kind: "tool_call", ToolID: "t1", Title: "Terminal", ToolKind: "execute", Status: "pending"})
	b.tool(Update{Kind: "tool_call_update", ToolID: "t1", Title: "cd /w; gitleaks git .", Command: "cd /w; gitleaks git ."})
	b.tool(Update{Kind: "tool_call_update", ToolID: "t1", Command: "cd /w; gitleaks git .", Content: "Run gitleaks on the history"})
	b.tool(Update{Kind: "tool_call_update", ToolID: "t1", Status: "completed", Content: "```console\nscanning\n\n1 commit\nleaks found: 3\n```"})
	var got []map[string]string
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m struct {
			Fields map[string]string `json:"fields"`
		}
		_ = json.Unmarshal([]byte(line), &m)
		got = append(got, m.Fields)
	}
	if len(got) != 4 {
		t.Fatalf("events %v", got)
	}
	if got[0]["summary"] != "gitleaks git ." || got[0]["id"] != "t1" {
		t.Fatalf("first: %v (placeholder must not show, cd stripped)", got[0])
	}
	if got[1]["summary"] != "Run gitleaks on the history" || got[1]["detail"] != "gitleaks git ." {
		t.Fatalf("description: %v", got[1])
	}
	if got[2]["status"] != "completed" || got[3]["tool"] != "output" || got[3]["summary"] != "scanning\n1 commit\nleaks found: 3" {
		t.Fatalf("completed: %v %v", got[2], got[3])
	}
}

func TestFirstSentence(t *testing.T) {
	if got := firstSentence("Checking the target is a git repo before scanning history. Then I will."); got != "Checking the target is a git repo before scanning history" {
		t.Fatal(got)
	}
}

func TestToolTitleThatIsTheCommandShowsOnce(t *testing.T) {
	var buf bytes.Buffer
	b := &bridge{o: BridgeOptions{Out: &buf, Cwd: "/w"}}
	long := "W=$LAB_WORKSPACE; mkdir -p $W/evidence/artifacts; A=$W/evidence/artifacts; cd /home/agent/target; gitleaks git --redact ."
	b.tool(Update{Kind: "tool_call_update", ToolID: "t1", Title: long[:60], Command: long})
	var m struct {
		Fields map[string]string `json:"fields"`
	}
	_ = json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &m)
	if m.Fields["summary"] != long || m.Fields["detail"] != "" {
		t.Fatalf("fields %v", m.Fields)
	}
}

func TestCodexTerminalOutputAndBoldThought(t *testing.T) {
	var buf bytes.Buffer
	b := &bridge{o: BridgeOptions{Out: &buf, Cwd: "/w"}}
	b.tool(Update{Kind: "tool_call", ToolID: "e1", Title: "gitleaks git .", Command: "gitleaks git .", ToolKind: "execute", Status: "in_progress"})
	b.tool(Update{Kind: "tool_call_update", ToolID: "e1", Delta: "scanning\n"})
	b.tool(Update{Kind: "tool_call_update", ToolID: "e1", Status: "completed", Delta: "leaks found: 3\n"})
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	var last struct {
		Fields map[string]string `json:"fields"`
	}
	_ = json.Unmarshal([]byte(lines[len(lines)-1]), &last)
	if last.Fields["tool"] != "output" || last.Fields["summary"] != "scanning\nleaks found: 3" {
		t.Fatalf("output %v", last.Fields)
	}
	if got := firstSentence("**Starting Gitleaks scan**"); got != "Starting Gitleaks scan" {
		t.Fatal(got)
	}
}

func TestStripWorkspacePrefix(t *testing.T) {
	b := &bridge{o: BridgeOptions{Cwd: "/Users/tester/.burner/runs/r/workspace"}}
	for in, want := range map[string]string{
		"W=/Users/tester/.burner/runs/r/workspace; cd $W && trufflehog git x > $W/a":  "trufflehog git x > $W/a",
		"W=/Users/tester/.burner/runs/r/workspace; cd /home/agent/target && gitleaks": "cd /home/agent/target && gitleaks",
		"cd /Users/tester/.burner/runs/r/workspace; cat a":                            "cat a",
		"cd /Users/tester/.burner/runs/r/workspace && cat a":                          "cat a",
		"W=/elsewhere; cd $W && ls":                                                   "W=/elsewhere; cd $W && ls",
	} {
		if got := b.stripCd(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestBridgeModelDefaultNeitherAsksNorSets(t *testing.T) {
	var asked []string
	_, dir, code := runFake(t, BridgeOptions{Permission: "auto", Model: ModelDefault}, func(id, q string) *string {
		asked = append(asked, id)
		v := "Finish"
		return &v
	})
	raw, _ := os.ReadFile(filepath.Join(dir, "acp-transcript.raw.jsonl"))
	for _, a := range asked {
		if a == "acp-model" {
			t.Fatal("asked for the model")
		}
	}
	if code != 0 || strings.Contains(string(raw), `"configId":"model"`) {
		t.Fatalf("exit %d or the model was set", code)
	}
}
