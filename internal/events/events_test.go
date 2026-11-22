package events

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixture = "../../tests/fixtures/events/run.ndjson"

func TestDecodesRunnerFixture(t *testing.T) {
	f, err := os.Open(fixture)
	if err != nil {
		t.Skip("runner fixture not present")
	}
	defer f.Close()
	var got []Event
	if err := Read(f, func(e Event) { got = append(got, e) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 13 || got[0].Type != "step" || got[12].Type != "done" {
		t.Fatalf("decoded %d events", len(got))
	}
	for i, e := range got {
		if e.Seq != i {
			t.Fatalf("seq %d at %d", e.Seq, i)
		}
	}
	if got[5].Type != "ask" || len(got[5].Choices) != 2 || got[8].By != "timeout" || got[8].Value != nil {
		t.Fatalf("ask/answer: %+v %+v", got[5], got[8])
	}
}

func TestCleansAgentText(t *testing.T) {
	line := `{"schema_version":"1","type":"ask","seq":1,"ts":"t","run_id":"r","ask_id":"a1","question":"ok?\u001b]52;c;cm0gLXJm\u0007","choices":["yes\u001b[2A","no"],"allow_text":false,"timeout_s":5}`
	e, err := Decode([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if e.Question != "ok?" || e.Choices[0] != "yes" {
		t.Fatalf("not cleaned: %q %q", e.Question, e.Choices)
	}
}

func TestSkipsUnknownAndRejectsBadAskID(t *testing.T) {
	if _, err := Decode([]byte(`{"schema_version":"1","type":"future","seq":1}`)); err != ErrSkip {
		t.Fatalf("unknown type: %v", err)
	}
	if _, err := Decode([]byte(`{"schema_version":"2","type":"step","seq":1}`)); err != ErrSkip {
		t.Fatalf("unknown version: %v", err)
	}
	if _, err := Decode([]byte(`{"schema_version":"1","type":"ask","seq":1,"ask_id":"../x"}`)); err == nil {
		t.Fatal("bad ask_id accepted")
	}
}

func TestAnswerOverSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "ev")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan map[string]string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var req map[string]string
		json.NewDecoder(c).Decode(&req)
		got <- req
		c.Write([]byte(`{"ok":true}` + "\n"))
	}()
	if err := Answer(sock, "a1", "no"); err != nil {
		t.Fatal(err)
	}
	if req := <-got; req["ask_id"] != "a1" || req["value"] != "no" {
		t.Fatalf("sent %v", req)
	}
	if err := Answer(filepath.Join(dir, "missing.sock"), "a1", "x"); err == nil {
		t.Fatal("missing socket accepted")
	}
	link := filepath.Join(dir, "link.sock")
	os.Symlink(sock, link)
	if err := Answer(link, "a1", "x"); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("symlink accepted: %v", err)
	}
}

func TestRawRoundTripKeepsRequiredFields(t *testing.T) {
	f, err := os.ReadFile(fixture)
	if err != nil {
		t.Skip("fixture missing")
	}
	for _, line := range strings.Split(strings.TrimSpace(string(f)), "\n") {
		e, err := Decode([]byte(line))
		if err != nil {
			t.Fatal(err)
		}
		var orig, back map[string]any
		json.Unmarshal([]byte(line), &orig)
		out, _ := json.Marshal(e)
		json.Unmarshal(out, &back)
		for k := range orig {
			if _, ok := back[k]; !ok {
				t.Fatalf("%s lost field %q: %s", e.Type, k, out)
			}
		}
	}
}

func TestOversizedLineDoesNotStopTheStream(t *testing.T) {
	big := `{"schema_version":"1","type":"agent.message","seq":0,"ts":"t","run_id":"r","text":"` + strings.Repeat("x", MaxLine+10) + `"}`
	done := `{"schema_version":"1","type":"done","seq":1,"ts":"t","run_id":"r","exit_code":0,"report":null}`
	var got []Event
	if err := Read(strings.NewReader(big+"\n"+done+"\n"), func(e Event) { got = append(got, e) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Type != "done" {
		t.Fatalf("got %+v", got)
	}
}

func TestSocketPathRejectsTraversal(t *testing.T) {
	for _, bad := range []string{"..", ".", "../x", "a/b", ""} {
		if SocketPath("/runs", bad) != "" {
			t.Fatalf("accepted %q", bad)
		}
	}
	if err := Answer(SocketPath("/runs", ".."), "a1", "x"); err == nil {
		t.Fatal("answer to invalid run id accepted")
	}
}
