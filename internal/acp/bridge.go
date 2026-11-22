package acp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/BRYANN2K/sbx-burner/internal/sanitize"
)

// Profile is what burner knows about one agent's ACP server: which value of
// its "mode" option means full trust (the sandbox is the boundary) and which
// one makes it ask before risky actions. Values are only used when the agent
// offers them.
type Profile struct {
	ModeOption string
	FullTrust  string // --permission auto
	AskFirst   string // --permission ask
	// Unlisted says how a --model outside the offered list reaches the
	// agent (lab/sbx.py acp_model_unlisted): "config_option" sends it with
	// session/set_config_option anyway, "env" means the runner set it in
	// the adapter's environment at start, "" refuses it.
	Unlisted string
}

// Profiles lists the agents whose ACP path is wired and tested in sbx.
// lab/sbx.py AGENTS[...].acp must name the same agents.
var Profiles = map[string]Profile{
	// Verified 2026-11-22 against @agentclientprotocol/codex-acp 2.9.0 in
	// the sbx 0.54 codex kit: mode values read-only | workspace-write |
	// agent (auto review) | agent-full-access.
	"codex": {ModeOption: "mode", FullTrust: "agent-full-access", AskFirst: "agent", Unlisted: "env"},
	// Verified 2026-11-22 against @agentclientprotocol/claude-agent-acp
	// 0.109.1 (session-mode.js buildAvailableModes): mode values default
	// (Manual) | acceptEdits | plan | auto | bypassPermissions. The last is
	// offered only when the process is not root or IS_SANDBOX is set —
	// both hold inside sbx.
	"claude": {ModeOption: "mode", FullTrust: "bypassPermissions", AskFirst: "default", Unlisted: "config_option"},
	// Verified 2026-11-22 against cursor-agent 2026.11.22 (`cursor-agent
	// acp`) in the sbx 0.54 cursor kit: mode values agent | plan | ask.
	// "agent" is the only mode with tool access; "plan" is read-only — the
	// closest to ask-before-acting the CLI offers.
	"cursor": {ModeOption: "mode", FullTrust: "agent", AskFirst: "plan"},
	// Verified 2026-11-22 against opencode 2.3.2 (`opencode acp`) in the
	// sbx 0.54 opencode kit: mode values build | plan.
	"opencode": {ModeOption: "mode", FullTrust: "build", AskFirst: "plan"},
	// Verified 2026-11-22 against devin 3000.14.30821 (`devin acp`) in the
	// sbx 0.54 devin kit: mode values accept-edits | smart | ask | plan |
	// bypass. "bypass" is Devin's auto-approve-all; "accept-edits" is its
	// default Code mode.
	"devin": {ModeOption: "mode", FullTrust: "bypass", AskFirst: "accept-edits"},
}

// BridgeOptions drive one ACP run inside a sandbox.
type BridgeOptions struct {
	Agent      string
	Permission string // auto | ask
	Model      string
	Prompt     string
	Cwd        string // workspace path inside the sandbox
	Transcript string // host path of the raw transcript (R12), in the run dir
	Unattended bool   // no operator: never ask (model default, no follow-up turns)
	// Probe: initialize and session/new only, write the model list next to
	// the transcript, and stop. No prompt is sent.
	Probe    bool
	Argv     []string
	In       io.Reader // runner → bridge: {"t":"answer","id":...,"value":...}
	Out      io.Writer // bridge → runner: event | ask | log lines
	MaxTurns int
}

// ModelsFile is written next to the transcript after session/new.
const ModelsFile = "acp-models.json"

// Models is the content of ModelsFile and of burner's model cache.
type Models struct {
	Agent   string        `json:"agent"`
	Option  string        `json:"option"`
	Current string        `json:"current"`
	Values  []ConfigValue `json:"values"`
	Seen    string        `json:"seen"`
	// Version is the agent's own version (ACP agentInfo), when it sent one:
	// the cache is per agent version.
	Version string `json:"version,omitempty"`
}

type bridge struct {
	o      BridgeOptions
	wmu    sync.Mutex
	amu    sync.Mutex
	asks   map[string]chan *string
	nask   int
	buf    strings.Builder
	bufMu  sync.Mutex
	tapMu  sync.Mutex
	tapW   *bufio.Writer
	tapN   int64
	client *Client
}

// MaxTranscript caps the raw transcript on disk.
const MaxTranscript = 128 << 20

// RunBridge runs the agent's ACP server through argv (an `sbx exec -i`
// command), sends the task, streams updates as run events, and asks the
// operator through the runner. It returns the process exit code.
func RunBridge(ctx context.Context, o BridgeOptions) int {
	if o.MaxTurns <= 0 {
		o.MaxTurns = 20
	}
	prof, ok := Profiles[o.Agent]
	if !ok {
		fmt.Fprintf(os.Stderr, "acp-bridge: ACP is not wired for %q\n", o.Agent)
		return 2
	}
	if len(o.Argv) == 0 {
		fmt.Fprintln(os.Stderr, "acp-bridge: no agent command after --")
		return 2
	}
	b := &bridge{o: o, asks: map[string]chan *string{}}
	if o.Transcript != "" {
		f, err := openTranscript(o.Transcript)
		if err != nil {
			fmt.Fprintf(os.Stderr, "acp-bridge: transcript: %v\n", err)
			return 2
		}
		defer f.Close()
		b.tapW = bufio.NewWriter(f)
		defer func() {
			b.tapMu.Lock()
			_ = b.tapW.Flush()
			b.tapMu.Unlock()
		}()
	}
	go b.readAnswers()

	cmd := exec.Command(o.Argv[0], o.Argv[1:]...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return b.fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return b.fatal(err)
	}
	cmd.Stderr = os.Stderr // the runner keeps it in logs/agent.log
	if err := cmd.Start(); err != nil {
		return b.fatal(err)
	}
	defer func() {
		_ = stdin.Close()
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}()

	var tap func(string, []byte)
	if b.tapW != nil {
		tap = b.tap
	}
	c := NewTapped(stdout, stdin, b, tap)
	b.client = c
	go func() {
		<-ctx.Done()
		_ = c.Cancel()
	}()

	if err := c.Initialize(ctx, "burner"); err != nil {
		return b.fatal(err)
	}
	if err := c.NewSession(ctx, o.Cwd); err != nil {
		return b.fatal(err)
	}
	b.writeModels()
	if o.Probe {
		return 0
	}

	// Speed: never turn on a paid fast mode; set it off when offered.
	for _, opt := range c.Options {
		if opt.Category == "speed" && opt.Current != "off" && hasValue(opt, "off") {
			if err := c.SetOption(ctx, opt.ID, "off"); err != nil {
				b.log("could not turn %s off: %v", opt.Name, err)
			}
		}
	}
	mode := prof.FullTrust
	if o.Permission == "ask" {
		mode = prof.AskFirst
	}
	if opt, ok := option(c.Options, prof.ModeOption); ok && mode != "" && hasValue(opt, mode) && opt.Current != mode {
		if err := c.SetOption(ctx, opt.ID, mode); err != nil {
			return b.fatal(err)
		}
	}
	if err := b.pickModel(ctx); err != nil {
		return b.fatal(err)
	}

	prompt := o.Prompt
	stop := ""
	for turn := 1; turn <= o.MaxTurns; turn++ {
		stop, err = c.Prompt(ctx, prompt)
		b.flush()
		if err != nil {
			return b.fatal(err)
		}
		if o.Unattended {
			break
		}
		v := b.ask(fmt.Sprintf("acp-turn-%d", turn),
			fmt.Sprintf("The agent ended its turn (%s). Send a note to continue, or pick Finish.", stop),
			[]string{"Finish"}, true)
		if v == nil || strings.TrimSpace(*v) == "" || *v == "Finish" {
			break
		}
		note, err := Notes(*v)
		if err != nil {
			b.log("note refused: %v", err)
			break
		}
		prompt = note
	}
	switch stop {
	case "end_turn", "max_tokens", "max_turn_requests":
		return 0
	default:
		b.log("the agent stopped: %s", stop)
		return 1
	}
}

func openTranscript(path string) (*os.File, error) {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("refusing a symlinked transcript path")
	}
	return os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
}

func (b *bridge) tap(dir string, line []byte) {
	b.tapMu.Lock()
	defer b.tapMu.Unlock()
	if b.tapN > MaxTranscript {
		return
	}
	rec, _ := json.Marshal(map[string]string{"ts": time.Now().UTC().Format(time.RFC3339Nano), "dir": dir, "raw": string(line)})
	n, _ := b.tapW.Write(append(rec, '\n'))
	b.tapN += int64(n)
}

func (b *bridge) emit(v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		return
	}
	b.wmu.Lock()
	defer b.wmu.Unlock()
	_, _ = b.o.Out.Write(append(raw, '\n'))
}

func (b *bridge) event(typ string, fields map[string]string) {
	b.emit(map[string]any{"t": "event", "type": typ, "fields": fields})
}

func (b *bridge) log(format string, a ...any) {
	b.emit(map[string]any{"t": "log", "text": fmt.Sprintf(format, a...)})
}

func (b *bridge) fatal(err error) int {
	b.flush()
	b.log("ACP session ended: %v", err)
	fmt.Fprintf(os.Stderr, "acp-bridge: %v\n", err)
	return 1
}

// ask sends a question to the operator through the runner and waits.
func (b *bridge) ask(id, question string, choices []string, allowText bool) *string {
	ch := make(chan *string, 1)
	b.amu.Lock()
	b.asks[id] = ch
	b.amu.Unlock()
	b.emit(map[string]any{"t": "ask", "id": id, "question": question, "choices": choices, "allow_text": allowText})
	return <-ch
}

func (b *bridge) readAnswers() {
	if b.o.In == nil {
		return
	}
	sc := bufio.NewScanner(b.o.In)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		var m struct {
			T     string  `json:"t"`
			ID    string  `json:"id"`
			Value *string `json:"value"`
		}
		if json.Unmarshal(sc.Bytes(), &m) != nil || m.T != "answer" {
			continue
		}
		b.amu.Lock()
		ch, ok := b.asks[m.ID]
		delete(b.asks, m.ID)
		b.amu.Unlock()
		if ok {
			ch <- m.Value
		}
	}
	// stdin closed: release every waiting question with "no answer".
	b.amu.Lock()
	for id, ch := range b.asks {
		ch <- nil
		delete(b.asks, id)
	}
	b.amu.Unlock()
}

func (b *bridge) writeModels() {
	opt, ok := b.client.Models()
	if (!ok && !b.o.Probe) || b.o.Transcript == "" {
		return
	}
	// A probe always writes: an agent with no model option has an empty list.
	if opt.Values == nil {
		opt.Values = []ConfigValue{}
	}
	m := Models{Agent: b.o.Agent, Option: opt.ID, Current: opt.Current, Values: opt.Values, Seen: time.Now().UTC().Format(time.RFC3339), Version: b.client.AgentVersion}
	raw, _ := json.MarshalIndent(m, "", "  ")
	_ = os.WriteFile(filepath.Join(filepath.Dir(b.o.Transcript), ModelsFile), raw, 0o600)
}

func (b *bridge) pickModel(ctx context.Context) error {
	opt, ok := b.client.Models()
	if b.o.Model != "" {
		if !ok {
			return fmt.Errorf("--model %s: the agent offers no model choice", b.o.Model)
		}
		if !hasValue(opt, b.o.Model) {
			switch Profiles[b.o.Agent].Unlisted {
			case "config_option":
				b.log("model %s is not in %s's list; sending it as is", b.o.Model, b.o.Agent)
				return b.client.SetUnlisted(ctx, opt.ID, b.o.Model)
			case "env":
				b.log("model %s set in %s's session config at start", b.o.Model, b.o.Agent)
				return nil
			}
			ids := make([]string, 0, len(opt.Values))
			for _, v := range opt.Values {
				ids = append(ids, v.Value)
			}
			return fmt.Errorf("--model %s is not offered by %s (models: %s)", b.o.Model, b.o.Agent, strings.Join(ids, ", "))
		}
		if opt.Current == b.o.Model {
			return nil
		}
		return b.client.SetOption(ctx, opt.ID, b.o.Model)
	}
	if !ok || b.o.Unattended || len(opt.Values) < 2 {
		return nil
	}
	choices := []string{opt.Current}
	for _, v := range opt.Values {
		if v.Value != opt.Current && len(choices) < sanitize.MaxChoices {
			choices = append(choices, v.Value)
		}
	}
	v := b.ask("acp-model", fmt.Sprintf("Model for this run (%s)?", b.o.Agent), choices, false)
	if v == nil || *v == "" || *v == opt.Current || !hasValue(opt, *v) {
		return nil
	}
	return b.client.SetOption(ctx, opt.ID, *v)
}

// Update coalesces message chunks into readable agent.message events.
func (b *bridge) Update(u Update) {
	switch u.Kind {
	case "agent_message_chunk":
		b.bufMu.Lock()
		b.buf.WriteString(u.Text)
		long := b.buf.Len() > 3000
		b.bufMu.Unlock()
		if long {
			b.flush()
		}
	case "tool_call":
		b.flush()
		tool := u.ToolKind
		if tool == "" {
			tool = "tool"
		}
		title := u.Title
		if title == "" {
			title = "tool call"
		}
		b.event("agent.tool", map[string]string{"tool": tool, "summary": title})
	case "tool_call_update":
		if u.Status == "failed" && u.Title != "" {
			b.event("agent.tool", map[string]string{"tool": "failed", "summary": u.Title})
		}
	}
}

func (b *bridge) flush() {
	b.bufMu.Lock()
	text := strings.TrimSpace(b.buf.String())
	b.buf.Reset()
	b.bufMu.Unlock()
	if text != "" {
		b.event("agent.message", map[string]string{"text": text})
	}
}

// Permission applies the run's policy (R3: only an offered option id).
// Full trust allows a request once and never picks allow_always; with no
// allow_once on offer the request is rejected once (or cancelled). In ask
// mode the operator's pick maps back by position, never by name.
func (b *bridge) Permission(p Permission) (string, bool) {
	title := p.Title
	if title == "" {
		title = "an action"
	}
	if b.o.Permission != "ask" {
		if o, ok := pickKind(p.Options, "allow_once"); ok {
			b.event("agent.tool", map[string]string{"tool": "permission", "summary": fmt.Sprintf("auto-allowed once (%s %q): %s", o.Kind, o.Name, title)})
			return o.ID, true
		}
		id, ok := rejectOnce(p.Options)
		b.event("agent.tool", map[string]string{"tool": "permission", "summary": "refused (no allow_once offered): " + title})
		return id, ok
	}
	b.amu.Lock()
	b.nask++
	id := fmt.Sprintf("acp-perm-%d", b.nask)
	b.amu.Unlock()
	labels := make([]string, 0, len(p.Options))
	for _, o := range p.Options {
		labels = append(labels, fmt.Sprintf("%s (%s)", o.Name, o.Kind))
	}
	labels = uniqueLabels(labels)
	v := b.ask(id, "The agent asks permission: "+title, labels, false)
	if v != nil {
		for i, l := range labels {
			if l == *v {
				return p.Options[i].ID, true
			}
		}
	}
	return rejectOnce(p.Options)
}

func pickKind(opts []Option, kind string) (Option, bool) {
	for _, o := range opts {
		if o.Kind == kind {
			return o, true
		}
	}
	return Option{}, false
}

// rejectOnce answers "no" without a lasting rule: reject_once, else
// cancelled. reject_always is never chosen for the operator.
func rejectOnce(opts []Option) (string, bool) {
	if o, ok := pickKind(opts, "reject_once"); ok {
		return o.ID, true
	}
	return "", false
}

// uniqueLabels suffixes repeated labels with their position.
func uniqueLabels(in []string) []string {
	used := map[string]bool{}
	out := make([]string, len(in))
	for i, l := range in {
		for n := i + 1; used[l]; n++ {
			l = fmt.Sprintf("%s #%d", in[i], n)
		}
		used[l] = true
		out[i] = l
	}
	return out
}

func option(opts []ConfigOption, id string) (ConfigOption, bool) {
	for _, o := range opts {
		if o.ID == id {
			return o, true
		}
	}
	return ConfigOption{}, false
}

func hasValue(o ConfigOption, v string) bool {
	for _, x := range o.Values {
		if x.Value == v {
			return true
		}
	}
	return false
}
