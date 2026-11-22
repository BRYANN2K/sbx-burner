// Package events reads the runner's live event stream
// (lab/schema/events.schema.json, schema_version "1") and talks to the
// run's control socket to answer the agent's questions.
//
// Every agent-controlled string is cleaned before it leaves this package:
// the agent runs with full trust in the sandbox, so its text is untrusted
// on the user's terminal.
package events

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/BRYANN2K/sbx-burner/internal/sanitize"
)

// Event is one line of the stream. Fields not used by a type stay zero.
type Event struct {
	SchemaVersion string `json:"schema_version"`
	Type          string `json:"type"`
	Seq           int    `json:"seq"`
	TS            string `json:"ts"`
	RunID         string `json:"run_id"`

	Name   string `json:"name,omitempty"`   // step
	Status string `json:"status,omitempty"` // step, finding, done
	Detail string `json:"detail,omitempty"` // step

	Agent   string `json:"agent,omitempty"`   // agent.*
	Text    string `json:"text,omitempty"`    // agent.message
	Tool    string `json:"tool,omitempty"`    // agent.tool
	Summary string `json:"summary,omitempty"` // agent.tool

	ID       string `json:"id,omitempty"` // finding
	Title    string `json:"title,omitempty"`
	Severity string `json:"severity,omitempty"`
	CVSS     string `json:"cvss,omitempty"`

	Host string `json:"host,omitempty"` // blocked

	AskID     string   `json:"ask_id,omitempty"` // ask, answer
	Question  string   `json:"question,omitempty"`
	Choices   []string `json:"choices,omitempty"`
	AllowText bool     `json:"allow_text,omitempty"`
	TimeoutS  int      `json:"timeout_s,omitempty"`
	By        string   `json:"by,omitempty"`    // answer: user|timeout|skip|forged
	Value     *string  `json:"value,omitempty"` // answer

	Argv []string `json:"argv,omitempty"` // handoff: the command burner runs on the terminal

	ExitCode int    `json:"exit_code,omitempty"` // done
	Report   string `json:"report,omitempty"`

	// Raw is the event re-encoded from the original fields (nulls, zeros
	// and required keys kept) with agent-controlled strings cleaned. Use
	// it to pass events on (--json, MCP); it stays schema-valid.
	Raw json.RawMessage `json:"-"`
}

// MarshalJSON emits Raw, so passing an Event on keeps it schema-valid.
func (e Event) MarshalJSON() ([]byte, error) {
	if len(e.Raw) > 0 {
		return e.Raw, nil
	}
	type plain Event
	return json.Marshal(plain(e))
}

// agent-controlled string fields cleaned in Raw.
var agentFields = map[string]int{"text": 4096, "summary": 4096, "tool": 256, "question": 4096, "detail": 4096, "title": 4096, "value": 4096, "host": 300}

// Known event types; readers skip the others (forward compatible).
var Known = map[string]bool{"step": true, "agent.message": true, "agent.tool": true, "finding": true, "blocked": true, "ask": true, "answer": true, "handoff": true, "done": true}

var askIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ErrSkip marks an event of an unknown type or version.
var ErrSkip = errors.New("skip")

// Decode parses and cleans one line.
func Decode(line []byte) (Event, error) {
	var e Event
	if err := json.Unmarshal(line, &e); err != nil {
		return e, err
	}
	if e.SchemaVersion != "1" || !Known[e.Type] {
		return e, ErrSkip
	}
	if (e.Type == "ask" || e.Type == "answer") && !askIDRE.MatchString(e.AskID) {
		return e, fmt.Errorf("invalid ask_id %q", e.AskID)
	}
	clean(&e)
	var m map[string]any
	if err := json.Unmarshal(line, &m); err == nil {
		for k, max := range agentFields {
			if v, ok := m[k].(string); ok {
				m[k] = sanitize.Text(v, max)
			}
		}
		if cs, ok := m["choices"].([]any); ok {
			clean := []any{}
			for i, c := range cs {
				if str, ok := c.(string); ok && i < sanitize.MaxChoices {
					clean = append(clean, sanitize.Line(str, 512))
				}
			}
			m["choices"] = clean
		}
		e.Raw, _ = json.Marshal(m)
	}
	return e, nil
}

func clean(e *Event) {
	raw := *e
	l := sanitize.Line
	e.RunID, e.Name, e.Status, e.Agent, e.Tool = l(e.RunID, 120), l(e.Name, 80), l(e.Status, 20), l(e.Agent, 20), l(e.Tool, 80)
	e.Detail, e.Summary, e.Host = l(e.Detail, 500), l(e.Summary, 500), l(e.Host, 300)
	e.Text = sanitize.Text(e.Text, sanitize.MaxField)
	e.Question = sanitize.Text(e.Question, sanitize.MaxField)
	e.Choices = sanitize.Choices(e.Choices)
	e.ID, e.Title, e.Severity, e.CVSS, e.By = l(e.ID, 40), l(e.Title, 300), l(e.Severity, 20), l(e.CVSS, 120), l(e.By, 20)
	if e.Type == "agent.tool" {
		// A tool call's id (up to 128) and, for tool "output", its last
		// lines: line breaks are kept.
		e.ID = l(raw.ID, 128)
		if e.Tool == "output" {
			e.Summary = sanitize.Text(raw.Summary, 1600)
		}
	}
	e.Report = l(e.Report, 500)
	if e.Value != nil {
		v := sanitize.Text(*e.Value, sanitize.MaxField)
		e.Value = &v
	}
}

// Read decodes a stream until EOF, calling fn per event. Unknown types are
// skipped; a malformed line stops nothing.
// A line longer than MaxLine is discarded and reading goes on, so one
// oversized event cannot freeze the live view or lose "done".
func Read(r io.Reader, fn func(Event)) error {
	br := bufio.NewReaderSize(r, 64*1024)
	for {
		line, tooLong, err := readLine(br)
		if len(line) > 0 && !tooLong {
			if e, derr := Decode(line); derr == nil {
				fn(e)
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// MaxLine caps one event line.
const MaxLine = 1 << 20

func readLine(br *bufio.Reader) ([]byte, bool, error) {
	var buf []byte
	tooLong := false
	for {
		chunk, isPrefix, err := br.ReadLine()
		if !tooLong {
			buf = append(buf, chunk...)
			if len(buf) > MaxLine {
				tooLong, buf = true, nil
			}
		}
		if err != nil || !isPrefix {
			return buf, tooLong, err
		}
	}
}

var runIDRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// SocketPath is the control socket of a run: <runs-dir>/<run_id>/control.sock.
// An invalid run id yields "" (Answer then refuses).
func SocketPath(runsDir, runID string) string {
	if !runIDRE.MatchString(runID) || runID == "." || runID == ".." {
		return ""
	}
	return filepath.Join(runsDir, runID, "control.sock")
}

// Answer sends {ask_id, value} to the run's control socket and waits for
// {"ok":true} or {"error":"…"}. The socket must be a real socket owned by
// the user (no symlink).
func Answer(sock, askID, value string) error {
	if !askIDRE.MatchString(askID) {
		return fmt.Errorf("invalid ask id %q", askID)
	}
	if len(value) > sanitize.MaxField {
		return fmt.Errorf("answer longer than %d bytes", sanitize.MaxField)
	}
	if sock == "" {
		return errors.New("invalid run id")
	}
	st, err := os.Lstat(sock)
	if err != nil {
		return fmt.Errorf("no control socket at %s (run finished?)", sock)
	}
	if st.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s is not a socket", sock)
	}
	if err := ownedByMe(st); err != nil {
		return err
	}
	if pst, err := os.Stat(filepath.Dir(sock)); err != nil || pst.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: parent directory is writable by others", sock)
	}
	conn, err := net.DialTimeout("unix", sock, 3*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	req, _ := json.Marshal(map[string]string{"ask_id": askID, "value": value})
	if _, err := conn.Write(append(req, '\n')); err != nil {
		return err
	}
	var resp struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return fmt.Errorf("control socket: %w", err)
	}
	if !resp.OK {
		return errors.New(sanitize.Line(resp.Error, 300))
	}
	return nil
}

func ownedByMe(st os.FileInfo) error {
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != os.Getuid() {
		return errors.New("control socket is owned by another user")
	}
	return nil
}

// InteractiveAsk is the host ask the runner holds while the operator uses
// the agent's own TUI (lab/runner.py INTERACTIVE_ASK).
const InteractiveAsk = "agent-tui"

var envArgRE = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*=`)

// HandoffArgv checks a handoff event before burner runs it on the user's
// terminal. Only the runner's exact shape passes:
//
//	sbx exec -it [--workdir <workspace>] [--env KEY=VALUE]... <sandbox> -- CMD...
//
// for this run (runID, pinned by the caller from the first event), its
// sandbox and its workspace; every other token before "--" is refused.
func HandoffArgv(e Event, runID, sandbox, workspace string) ([]string, error) {
	a := e.Argv
	if e.Type != "handoff" || e.Name != "agent" || len(a) < 6 || len(a) > 64 {
		return nil, errors.New("not an agent handoff")
	}
	if runID == "" || e.RunID != runID {
		return nil, fmt.Errorf("handoff for another run (%s)", e.RunID)
	}
	for _, x := range a {
		if len(x) > 64<<10 || strings.ContainsRune(x, 0) {
			return nil, errors.New("handoff argument too long or not text")
		}
	}
	if a[0] != "sbx" || a[1] != "exec" || a[2] != "-it" {
		return nil, errors.New("handoff is not `sbx exec -it`")
	}
	i := 3
	workdir := false
	for i < len(a) && strings.HasPrefix(a[i], "-") {
		switch a[i] {
		case "--workdir":
			if workdir || i+1 >= len(a) || a[i+1] != workspace {
				return nil, errors.New("handoff --workdir is not this run's workspace")
			}
			workdir = true
			i += 2
		case "--env":
			if i+1 >= len(a) || !envArgRE.MatchString(a[i+1]) {
				return nil, errors.New("handoff --env is not KEY=VALUE")
			}
			i += 2
		default:
			return nil, fmt.Errorf("handoff flag %q is not allowed", a[i])
		}
	}
	if i+2 >= len(a) || a[i] != sandbox || a[i+1] != "--" {
		return nil, fmt.Errorf("handoff must target sandbox %s then --", sandbox)
	}
	return append([]string{}, a...), nil
}

// SandboxForRun is the runner's sandbox name for a run id
// ("YYYYMMDD-HHMMSS-<recipe>" → "lab-<recipe>"[:48] + "-HHMMSS").
func SandboxForRun(runID string) string {
	if len(runID) < 17 || runID[8] != '-' || runID[15] != '-' {
		return ""
	}
	base := "lab-" + runID[16:]
	if len(base) > 48 {
		base = base[:48]
	}
	return strings.TrimRight(base, "-") + "-" + runID[9:15]
}
