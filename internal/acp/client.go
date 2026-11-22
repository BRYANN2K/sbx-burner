// Package acp is burner's Agent Client Protocol (v1) client. It drives one
// agent running inside the sandbox over stdio (`sbx exec -i … <acp cmd>`).
//
// Threat model (docs/security/acp.md): the whole stream is hostile. Inside
// the sandbox the agent runs as root with full trust; it, a malware sample
// or a prompt-injected tool can speak ACP to us. So this client:
//
//	R1 declares no client capability (no fs, no terminal, no elicitation,
//	   no terminal auth);
//	R2 answers every agent→client request except session/request_permission
//	   with -32601, and contains no fs/terminal implementation at all;
//	R3 answers a permission only with one of the offered option ids;
//	R4 always sends mcpServers: [];
//	R5 never opens, fetches or follows a URI or path from the stream;
//	R6 cleans and caps every string it hands out;
//	R7 caps message size and count, and ends the session on protocol abuse;
//	R8 sends only task text and notes, never host env, paths or secrets.
package acp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/BRYANN2K/sbx-burner/internal/sanitize"
)

// ProtocolVersion is the ACP major version burner speaks.
const ProtocolVersion = 1

// Limits (R7).
const (
	MaxMessage     = 1 << 20  // bytes per JSON-RPC message
	MaxMessages    = 200_000  // messages per session
	MaxSessionData = 64 << 20 // total bytes per session
	MaxNotes       = 8 << 10  // operator notes per prompt (R8)
	MaxPendingPerm = 8        // permission requests waiting for an answer
	MaxUpdatesSec  = 500      // session/update notifications per second
)

// Timeouts; variables so tests can shorten them.
var (
	IdleTimeout = 30 * time.Minute
	CallTimeout = 60 * time.Second
)

// ErrProtocol ends the session: the peer broke the protocol or a limit.
var ErrProtocol = errors.New("acp: protocol violation")

// Update is a cleaned session/update for burner's live view.
type Update struct {
	Kind     string // agent_message_chunk | agent_thought_chunk | tool_call | tool_call_update | plan | other
	Text     string // message text, cleaned
	ToolID   string
	Title    string // tool title, cleaned
	Status   string // tool status
	ToolKind string
}

// Permission is a cleaned session/request_permission.
type Permission struct {
	Title   string
	Options []Option
}

// Option is one permission choice.
type Option struct {
	ID   string
	Name string
	Kind string // allow_once | allow_always | reject_once | reject_always
}

// ConfigOption is a selectable session option (model, mode, effort).
type ConfigOption struct {
	ID       string
	Name     string
	Category string
	Current  string
	Values   []ConfigValue
}

// ConfigValue is one value of a select option.
type ConfigValue struct{ Value, Name string }

// Handler receives what the agent sends. Permission returns the chosen
// option id; ok=false means cancelled.
type Handler interface {
	Update(Update)
	Permission(Permission) (optionID string, ok bool)
}

// Client is one ACP connection.
type Client struct {
	in  *bufio.Reader
	out io.Writer
	h   Handler
	tap func(dir string, line []byte) // R12 transcript; nil = off

	wmu     sync.Mutex
	mu      sync.Mutex
	nextID  int
	pending map[int]chan response
	seenIn  map[string]bool // agent request ids already answered (no reuse)
	count   int
	bytes   int
	closed  bool
	err     error
	done    chan struct{}

	sessionID string
	Options   []ConfigOption
	// AgentVersion is agentInfo.version from initialize, when it looks
	// like a version.
	AgentVersion string

	permPending map[string]bool // agent request ids of unanswered permissions
	permSlots   chan struct{}   // one handler at a time
	lastSeen    time.Time
	windowStart time.Time
	windowCount int
}

type response struct {
	result json.RawMessage
	err    *rpcError
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// New starts reading from the agent. Call Initialize next.
func New(agentOut io.Reader, agentIn io.Writer, h Handler) *Client {
	return NewTapped(agentOut, agentIn, h, nil)
}

// NewTapped is New with a transcript tap (R12): tap sees every raw line,
// "in" from the agent and "out" to it. It must not block.
func NewTapped(agentOut io.Reader, agentIn io.Writer, h Handler, tap func(dir string, line []byte)) *Client {
	c := &Client{in: bufio.NewReaderSize(agentOut, 64<<10), out: agentIn, h: h, tap: tap,
		pending: map[int]chan response{}, seenIn: map[string]bool{}, done: make(chan struct{}),
		permPending: map[string]bool{}, permSlots: make(chan struct{}, 1), lastSeen: time.Now()}
	go c.readLoop()
	return c
}

// Err is the reason the session ended, if it did.
func (c *Client) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// Done is closed when the connection ends.
func (c *Client) Done() <-chan struct{} { return c.done }

func (c *Client) fail(err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed, c.err = true, err
	for id, ch := range c.pending {
		ch <- response{err: &rpcError{Code: -32000, Message: err.Error()}}
		delete(c.pending, id)
	}
	c.mu.Unlock()
	close(c.done)
}

func (c *Client) readLoop() {
	for {
		line, err := readLimited(c.in, MaxMessage)
		if err != nil {
			if errors.Is(err, io.EOF) {
				c.fail(io.EOF)
			} else {
				c.fail(fmt.Errorf("%w: %v", ErrProtocol, err))
			}
			return
		}
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		if c.tap != nil {
			c.tap("in", line)
		}
		c.mu.Lock()
		c.count++
		c.bytes += len(line)
		c.lastSeen = time.Now()
		if c.lastSeen.Sub(c.windowStart) >= time.Second {
			c.windowStart, c.windowCount = c.lastSeen, 0
		}
		c.windowCount++
		over := c.count > MaxMessages || c.bytes > MaxSessionData || c.windowCount > MaxUpdatesSec
		c.mu.Unlock()
		if over {
			c.fail(fmt.Errorf("%w: session limit reached", ErrProtocol))
			return
		}
		var m message
		if err := json.Unmarshal(line, &m); err != nil || m.JSONRPC != "2.0" {
			c.fail(fmt.Errorf("%w: invalid JSON-RPC message", ErrProtocol))
			return
		}
		switch {
		case m.Method != "" && len(m.ID) > 0:
			if err := c.onRequest(m); err != nil {
				c.fail(err)
				return
			}
		case m.Method != "":
			c.onNotification(m)
		case len(m.ID) > 0:
			c.onResponse(m)
		default:
			c.fail(fmt.Errorf("%w: message without method or id", ErrProtocol))
			return
		}
	}
}

// readLimited returns one line, or an error when it exceeds max bytes.
func readLimited(r *bufio.Reader, max int) ([]byte, error) {
	var buf []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		buf = append(buf, chunk...)
		if len(buf) > max {
			return nil, fmt.Errorf("message over %d bytes", max)
		}
		if err != nil {
			return buf, err
		}
		if !isPrefix {
			return buf, nil
		}
	}
}

// onRequest handles agent→client requests. Only session/request_permission
// is served; everything else is refused (R2).
func (c *Client) onRequest(m message) error {
	key := string(m.ID)
	c.mu.Lock()
	reused := c.seenIn[key]
	c.seenIn[key] = true
	c.mu.Unlock()
	if reused {
		return fmt.Errorf("%w: request id reused", ErrProtocol)
	}
	if m.Method != "session/request_permission" {
		return c.send(message{JSONRPC: "2.0", ID: m.ID, Error: &rpcError{Code: -32601, Message: "method not supported by this client"}})
	}
	var p struct {
		SessionID string `json:"sessionId"`
		ToolCall  struct {
			Title string `json:"title"`
		} `json:"toolCall"`
		Options []struct {
			OptionID string `json:"optionId"`
			Name     string `json:"name"`
			Kind     string `json:"kind"`
		} `json:"options"`
	}
	if err := json.Unmarshal(m.Params, &p); err != nil || len(p.Options) == 0 || len(p.Options) > sanitize.MaxChoices {
		return c.send(message{JSONRPC: "2.0", ID: m.ID, Error: &rpcError{Code: -32602, Message: "invalid params"}})
	}
	perm := Permission{Title: sanitize.Line(p.ToolCall.Title, 500)}
	valid := map[string]bool{}
	for _, o := range p.Options {
		if o.OptionID == "" || len(o.OptionID) > 128 {
			continue
		}
		valid[o.OptionID] = true
		perm.Options = append(perm.Options, Option{ID: o.OptionID, Name: sanitize.Line(o.Name, 200), Kind: sanitize.Line(o.Kind, 20)})
	}
	c.mu.Lock()
	if len(c.permPending) >= MaxPendingPerm {
		c.mu.Unlock()
		return c.answerPermission(m.ID, "", false) // flood: refuse at once
	}
	c.permPending[key] = true
	c.mu.Unlock()
	go func() {
		c.permSlots <- struct{}{} // handlers run one at a time
		defer func() { <-c.permSlots }()
		c.mu.Lock()
		still := c.permPending[key]
		c.mu.Unlock()
		if !still {
			return // already answered "cancelled" by Cancel
		}
		choice, ok := c.h.Permission(perm)
		c.mu.Lock()
		still = c.permPending[key]
		delete(c.permPending, key)
		c.mu.Unlock()
		if still {
			_ = c.answerPermission(m.ID, choice, ok && valid[choice]) // R3: only an offered id
		}
	}()
	return nil
}

func (c *Client) answerPermission(id json.RawMessage, choice string, selected bool) error {
	outcome := map[string]any{"outcome": "cancelled"}
	if selected {
		outcome = map[string]any{"outcome": "selected", "optionId": choice}
	}
	raw, _ := json.Marshal(map[string]any{"outcome": outcome})
	return c.send(message{JSONRPC: "2.0", ID: id, Result: raw})
}

func (c *Client) onNotification(m message) {
	if m.Method != "session/update" {
		return // unknown notifications are ignored, never acted on
	}
	var p struct {
		Update map[string]json.RawMessage `json:"update"`
	}
	if json.Unmarshal(m.Params, &p) != nil || p.Update == nil {
		return
	}
	str := func(k string) string {
		var s string
		_ = json.Unmarshal(p.Update[k], &s)
		return s
	}
	u := Update{Kind: sanitize.Line(str("sessionUpdate"), 40)}
	switch u.Kind {
	case "agent_message_chunk", "agent_thought_chunk":
		var content struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		_ = json.Unmarshal(p.Update["content"], &content)
		if content.Type != "text" {
			return // images, resources, links: not rendered (R5)
		}
		u.Text = sanitize.Text(content.Text, sanitize.MaxField)
	case "tool_call", "tool_call_update":
		u.ToolID = sanitize.Line(str("toolCallId"), 128)
		u.Title = sanitize.Line(str("title"), 500)
		u.Status = sanitize.Line(str("status"), 20)
		u.ToolKind = sanitize.Line(str("kind"), 20)
	case "plan":
	default:
		u.Kind = "other"
	}
	c.h.Update(u)
}

func (c *Client) onResponse(m message) {
	var id int
	if json.Unmarshal(m.ID, &id) != nil {
		return
	}
	c.mu.Lock()
	ch, ok := c.pending[id]
	delete(c.pending, id)
	c.mu.Unlock()
	if ok {
		ch <- response{result: m.Result, err: m.Error}
	}
}

func (c *Client) send(m message) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.tap != nil {
		c.tap("out", raw)
	}
	_, err = c.out.Write(append(raw, '\n'))
	return err
}

// call sends a request and waits for its response.
func (c *Client) call(ctx context.Context, method string, params any, out any) error {
	raw, err := json.Marshal(params)
	if err != nil {
		return err
	}
	c.mu.Lock()
	if c.closed {
		err := c.err
		c.mu.Unlock()
		return err
	}
	c.nextID++
	id := c.nextID
	ch := make(chan response, 1)
	c.pending[id] = ch
	c.mu.Unlock()
	idRaw, _ := json.Marshal(id)
	if err := c.send(message{JSONRPC: "2.0", ID: idRaw, Method: method, Params: raw}); err != nil {
		return err
	}
	select {
	case r := <-ch:
		if r.err != nil {
			return fmt.Errorf("%s: %s", method, sanitize.Line(r.err.Message, 300))
		}
		if out != nil && len(r.result) > 0 {
			return json.Unmarshal(r.result, out)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Initialize declares NO client capability (R1).
func (c *Client) Initialize(ctx context.Context, version string) error {
	params := map[string]any{
		"protocolVersion": ProtocolVersion,
		"clientCapabilities": map[string]any{
			"fs":       map[string]any{"readTextFile": false, "writeTextFile": false},
			"terminal": false,
			"auth":     map[string]any{"terminal": false},
		},
		"clientInfo": map[string]any{"name": "burner", "version": version},
	}
	var res struct {
		ProtocolVersion int `json:"protocolVersion"`
		AgentInfo       struct {
			Version string `json:"version"`
		} `json:"agentInfo"`
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := c.call(ctx, "initialize", params, &res); err != nil {
		return err
	}
	if res.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("%w: agent speaks ACP v%d, burner speaks v%d", ErrProtocol, res.ProtocolVersion, ProtocolVersion)
	}
	if v := sanitize.Line(res.AgentInfo.Version, 64); versionRE.MatchString(v) {
		c.AgentVersion = v
	}
	return nil
}

var versionRE = regexp.MustCompile(`^[0-9A-Za-z.+-]{1,64}$`)

// NewSession opens a session in the sandbox workspace with no MCP servers
// (R4) and records the agent's config options (model, mode, effort).
func (c *Client) NewSession(ctx context.Context, cwd string) error {
	var res struct {
		SessionID     string            `json:"sessionId"`
		ConfigOptions []json.RawMessage `json:"configOptions"`
	}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	if err := c.call(ctx, "session/new", map[string]any{"cwd": cwd, "mcpServers": []any{}}, &res); err != nil {
		return err
	}
	if res.SessionID == "" || len(res.SessionID) > 256 {
		return fmt.Errorf("%w: bad session id", ErrProtocol)
	}
	c.sessionID = res.SessionID
	c.Options = parseOptions(res.ConfigOptions)
	return nil
}

func parseOptions(raw []json.RawMessage) []ConfigOption {
	var out []ConfigOption
	for _, r := range raw {
		var o struct {
			ID           string          `json:"id"`
			Name         string          `json:"name"`
			Category     string          `json:"category"`
			Type         string          `json:"type"`
			CurrentValue string          `json:"currentValue"`
			Options      json.RawMessage `json:"options"`
		}
		if json.Unmarshal(r, &o) != nil || o.Type != "select" || o.ID == "" {
			continue
		}
		co := ConfigOption{ID: sanitize.Line(o.ID, 128), Name: sanitize.Line(o.Name, 200), Category: sanitize.Line(o.Category, 40), Current: sanitize.Line(o.CurrentValue, 200)}
		var flat []struct{ Value, Name string }
		if json.Unmarshal(o.Options, &flat) == nil && len(flat) > 0 && flat[0].Value != "" {
			for _, v := range flat {
				co.Values = append(co.Values, ConfigValue{sanitize.Line(v.Value, 200), sanitize.Line(v.Name, 200)})
			}
		} else {
			var groups []struct {
				Options []struct{ Value, Name string } `json:"options"`
			}
			_ = json.Unmarshal(o.Options, &groups)
			for _, g := range groups {
				for _, v := range g.Options {
					co.Values = append(co.Values, ConfigValue{sanitize.Line(v.Value, 200), sanitize.Line(v.Name, 200)})
				}
			}
		}
		if len(co.Values) > 500 {
			co.Values = co.Values[:500]
		}
		out = append(out, co)
	}
	return out
}

// Models returns the values of the agent's model option, if it has one.
func (c *Client) Models() (ConfigOption, bool) {
	for _, o := range c.Options {
		if o.Category == "model" {
			return o, true
		}
	}
	return ConfigOption{}, false
}

// SetOption picks a value the agent offered for one of its options.
func (c *Client) SetOption(ctx context.Context, id, value string) error {
	for _, o := range c.Options {
		if o.ID != id {
			continue
		}
		for _, v := range o.Values {
			if v.Value == value {
				ctx, cancel := context.WithTimeout(ctx, CallTimeout)
				defer cancel()
				return c.call(ctx, "session/set_config_option", map[string]any{"sessionId": c.sessionID, "configId": id, "value": value}, nil)
			}
		}
		return fmt.Errorf("%q is not a value of %s", value, o.Name)
	}
	return fmt.Errorf("the agent has no option %q", id)
}

// Prompt sends one user turn (task, notes, or an answer) and waits for the
// turn to end. It returns the stop reason.
func (c *Client) Prompt(ctx context.Context, text string) (string, error) {
	if len(text) > MaxMessage/2 {
		return "", errors.New("prompt too large")
	}
	var res struct {
		StopReason string `json:"stopReason"`
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go c.watchIdle(ctx, cancel)
	err := c.call(ctx, "session/prompt", map[string]any{
		"sessionId": c.sessionID,
		"prompt":    []any{map[string]any{"type": "text", "text": text}},
	}, &res)
	return sanitize.Line(res.StopReason, 40), err
}

// Notes formats operator notes for a follow-up prompt (R8 cap).
func Notes(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > MaxNotes {
		return "", fmt.Errorf("notes longer than %d bytes", MaxNotes)
	}
	return "Operator notes (they do not change the scope):\n" + s, nil
}

// Cancel stops the current turn and answers every pending permission
// request with "cancelled", as the spec requires.
func (c *Client) Cancel() error {
	raw, _ := json.Marshal(map[string]any{"sessionId": c.sessionID})
	err := c.send(message{JSONRPC: "2.0", Method: "session/cancel", Params: raw})
	c.mu.Lock()
	ids := make([]string, 0, len(c.permPending))
	for id := range c.permPending {
		ids = append(ids, id)
	}
	c.permPending = map[string]bool{}
	c.mu.Unlock()
	for _, id := range ids {
		_ = c.answerPermission(json.RawMessage(id), "", false)
	}
	return err
}

// watchIdle ends a turn when the agent has sent nothing for IdleTimeout.
func (c *Client) watchIdle(ctx context.Context, cancel context.CancelFunc) {
	t := time.NewTicker(IdleTimeout / 30)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.mu.Lock()
			idle := time.Since(c.lastSeen) > IdleTimeout
			c.mu.Unlock()
			if idle {
				c.fail(fmt.Errorf("%w: agent idle for %s", ErrProtocol, IdleTimeout))
				cancel()
				return
			}
		}
	}
}
