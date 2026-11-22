package tui

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/BRYANN2K/sbx-burner/internal/engine"
	"github.com/BRYANN2K/sbx-burner/internal/events"
	"github.com/BRYANN2K/sbx-burner/internal/sanitize"
)

// liveModel renders the runner's event stream (schema v1): steps, what the
// agent says and runs, findings, blocked hosts, and the agent's questions,
// answered in place.
type liveModel struct {
	opts    engine.RunOptions
	runsDir string
	started time.Time
	ended   time.Time

	log     []entry2
	stepAt  map[string]int
	asks    []events.Event
	cursor  int
	typing  bool
	answer  textinput.Model
	note    textinput.Model
	notes   bool
	runID   string
	done    *events.Event
	exit    int
	err     error
	finish  bool
	stop    bool
	stopAt  time.Time
	confirm bool     // second Ctrl+C: ask before leaving mid-teardown
	left    []string // sandboxes still listed by sbx after the run
	cancel  context.CancelFunc
	ch      chan tea.Msg
	stderr  *tail
	sc      scroller
	failed  string // last failed step, for its full log
	dropped int    // log entries dropped by the cap
	finds   map[string]string
	blocked int
	warn    string

	// Run screen v2.
	planText  string          // the engine's dry run, for steps, image and network
	chat      textinput.Model // messages to the agent over ACP
	chatOn    bool            // the chat input has the keyboard
	queue     []int           // log indexes of "you" messages not sent yet
	handoff   []string        // checked argv of the agent's own TUI (--interactive)
	tuiCmd    []string        // the agent's own TUI command, for t
	approval  *approvalCard   // credential binding to approve before the run starts
	autoAllow int             // ACP permissions auto-allowed (logged by the bridge)
	asked     int             // ACP permissions asked to the operator
	scopeHost []string        // hosts the scope file names
	scopeMode string

	inlineSteps bool // steps in the conversation (narrow terminals, no steps column)
}

type entry2 struct {
	kind string
	ev   events.Event
	text string

	closeTotal, closeDone, closeFail int // folded policy-close steps

	errLine string // a failed step's last error line
	queued  bool   // a "you" message waiting for the turn boundary

	cache  []string // rendered lines for cacheW
	cacheW int
}

// maxLog caps the live log; older entries are dropped in chunks.
const maxLog, trimChunk = 5000, 500

type eventMsg struct{ ev events.Event }
type runEndMsg struct {
	code int
	err  error
}
type answerSentMsg struct {
	askID string
	err   error
}
type noteSentMsg struct{ err error }

func newLive(o engine.RunOptions, now time.Time) *liveModel {
	l := &liveModel{opts: o, runsDir: o.RunsDir, started: now, cursor: -1, sc: scroller{follow: true}, stepAt: map[string]int{}, finds: map[string]string{}, stderr: &tail{max: 200}}
	ti := textinput.New()
	ti.Prompt = "❯ "
	ti.Placeholder = "type an answer"
	ti.CharLimit = sanitize.MaxField
	l.answer = ti
	n := textinput.New()
	n.Prompt = "❯ "
	n.Placeholder = "note for the agent, sent mid-run"
	n.CharLimit = 8192
	l.note = n
	c := textinput.New()
	c.Prompt = "❯ "
	c.Placeholder = "Message " + o.Agent + "…"
	c.CharLimit = 8192
	l.chat = c
	return l
}

func (l *liveModel) start(m model) tea.Cmd {
	l.notes = m.eng.Caps().MidRunNotes
	ch := make(chan tea.Msg, 512)
	l.ch = ch
	ctx, cancel := context.WithCancel(m.ctx)
	l.cancel = cancel
	eng, o, errw := m.eng, l.opts, l.stderr
	go func() {
		code, err := eng.Run(ctx, o, func(e events.Event) { ch <- eventMsg{e} }, errw)
		ch <- runEndMsg{code, err}
		close(ch)
	}()
	return waitCh(ch)
}

func waitCh(ch chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-ch
		if !ok {
			return nil
		}
		return msg
	}
}

func (l *liveModel) add(e events.Event) {
	// The run id is pinned by the first event and never updated: every
	// later check (handoff, sandbox name) compares against it.
	if l.runID == "" && e.RunID != "" {
		l.runID = e.RunID
	}
	defer l.trim()
	// The bridge logs every auto-allowed permission as a tool line: count
	// it for the side panel instead of filling the conversation.
	if e.Type == "agent.tool" && e.Tool == "permission" {
		if strings.HasPrefix(e.Summary, "auto-allowed") {
			l.autoAllow++
		}
		return
	}
	if e.Type == "handoff" {
		if argv, err := events.HandoffArgv(e, l.runID, events.SandboxForRun(l.runID), filepath.Join(l.runsDir, l.runID, "workspace")); err == nil {
			l.handoff = argv
		} else {
			l.warn = "refused handoff: " + err.Error()
		}
		return
	}
	if e.Type == "ask" && strings.HasPrefix(e.AskID, "acp-perm-") {
		l.asked++
	}
	// Agents report a tool call when it starts and when it ends.
	if e.Type == "agent.tool" && len(l.log) > 0 {
		last := l.log[len(l.log)-1]
		if last.kind == "agent.tool" && last.ev.Tool == e.Tool && last.ev.Summary == e.Summary {
			return
		}
	}
	switch e.Type {
	case "step":
		if strings.HasPrefix(e.Name, "policy-close:") {
			l.closeStep(e)
			return
		}
		if e.Status == "start" {
			l.stepAt[e.Name] = len(l.log)
			l.log = append(l.log, entry2{kind: "step", ev: e})
			return
		}
		errLine := ""
		if e.Status == "fail" {
			l.failed = e.Name
			if text, err := readTail(stepLogPath(l.runDir(), e.Name)); err == nil {
				errLine = lastError(text)
			}
		}
		if i, ok := l.stepAt[e.Name]; ok && l.log[i].ev.Status == "start" {
			l.log[i].ev = e
			l.log[i].errLine = errLine
			l.log[i].cache = nil
			return
		}
		l.log = append(l.log, entry2{kind: "step", ev: e, errLine: errLine})
	case "finding":
		l.finds[e.ID] = e.Status
		l.log = append(l.log, entry2{kind: e.Type, ev: e})
	case "blocked":
		l.blocked++
		l.log = append(l.log, entry2{kind: e.Type, ev: e})
	case "ask":
		l.asks = append(l.asks, e)
		l.log = append(l.log, entry2{kind: e.Type, ev: e})
	case "answer":
		l.dropAsk(e.AskID)
		l.log = append(l.log, entry2{kind: e.Type, ev: e})
	case "done":
		ev := e
		l.done = &ev
		l.log = append(l.log, entry2{kind: e.Type, ev: e})
	default:
		l.log = append(l.log, entry2{kind: e.Type, ev: e})
	}
}

// trim keeps the last maxLog entries and re-indexes the steps.
func (l *liveModel) trim() {
	if len(l.log) <= maxLog+trimChunk {
		return
	}
	n := len(l.log) - maxLog
	l.log = append([]entry2(nil), l.log[n:]...)
	l.dropped += n
	for k, i := range l.stepAt {
		if i < n {
			delete(l.stepAt, k)
		} else {
			l.stepAt[k] = i - n
		}
	}
}

// closeStep folds the per-host "policy-close:<host>" steps into one line.
func (l *liveModel) closeStep(e events.Event) {
	i, ok := l.stepAt["policy-close"]
	if !ok {
		i = len(l.log)
		l.stepAt["policy-close"] = i
		l.log = append(l.log, entry2{kind: "step", ev: events.Event{Type: "step", Name: "policy-close", Status: "start"}})
	}
	en := &l.log[i]
	en.cache = nil
	switch e.Status {
	case "start":
		en.closeTotal++
	case "ok":
		en.closeDone++
	case "fail":
		en.closeFail++
	}
	en.ev.Detail = fmt.Sprintf("%d / %d closed", en.closeDone, en.closeTotal)
	switch {
	case en.closeFail > 0:
		en.ev.Status = "fail"
		en.ev.Detail += fmt.Sprintf(", %d failed", en.closeFail)
	case en.closeDone == en.closeTotal:
		en.ev.Status = "ok"
	default:
		en.ev.Status = "start"
	}
}

func (l *liveModel) dropAsk(id string) {
	for i, a := range l.asks {
		if a.AskID == id {
			l.asks = append(l.asks[:i], l.asks[i+1:]...)
			if i == 0 {
				l.cursor, l.typing = -1, false
				l.answer.SetValue("")
				l.answer.Blur()
			}
			return
		}
	}
}

// runDir is where the report and evidence land.
func (l *liveModel) runDir() string {
	if l.done != nil && l.done.Report != "" {
		return filepath.Dir(l.done.Report)
	}
	if l.runID != "" {
		return filepath.Join(l.runsDir, l.runID)
	}
	return l.runsDir
}

func (m model) updateLive(msg tea.Msg) (tea.Model, tea.Cmd) {
	l := m.live
	switch msg := msg.(type) {
	case eventMsg:
		l.add(msg.ev)
		if msg.ev.Type == "ask" {
			return m, tea.Batch(waitCh(l.ch), m.onAsk(msg.ev))
		}
		return m, waitCh(l.ch)
	case handoffDoneMsg:
		note := l.opts.Agent + "'s own TUI closed"
		if msg.err != nil {
			note += ": " + sanitize.Line(msg.err.Error(), 200)
		}
		l.log = append(l.log, entry2{kind: "note", text: note})
		l.handoff = nil
		return m, l.send(msg.ask, "done")
	case agentTUIDoneMsg:
		if msg.err != nil {
			l.warn = "agent TUI: " + sanitize.Line(msg.err.Error(), 200)
		}
		return m, nil
	case approveDoneMsg:
		if l.approval == nil {
			return m, nil
		}
		ctx, eng, o := m.ctx, m.eng, l.opts
		return m, func() tea.Msg {
			t, c, err := eng.Plan(ctx, o)
			return replanMsg{text: t, code: c, err: err}
		}
	case replanMsg:
		if l.approval == nil {
			return m, nil
		}
		l.approval.busy = false
		if msg.err == nil && msg.code == 0 {
			l.approval = nil
			l.planText = sanitize.Text(msg.text, 64*1024)
			return m, l.start(m)
		}
		if c := approvalFromPlan(msg.text); c != nil {
			c.err = "the binding is still missing"
			l.approval = c
		} else {
			l.approval.err = "the plan is still refused; esc to read it"
		}
		return m, nil
	case runEndMsg:
		l.finish, l.exit, l.err, l.ended = true, msg.code, msg.err, m.cfg.Now()
		recordKept(m.ctx, l)
		m.setupRunDone()
		l.asks = nil
		m.out.Code = msg.code
		if l.done != nil {
			m.out.Report = l.done.Report
		}
		if l.done == nil {
			for _, s := range l.stderr.lines() {
				l.log = append(l.log, entry2{kind: "stderr", text: s})
			}
			if _, created := l.stepAt["create"]; created {
				return m, l.checkLeftover(m)
			}
		}
		return m, nil
	case leftoverMsg:
		l.left = msg.names
		if msg.err != nil {
			l.left = []string{""}
		}
		return m, nil
	case answerSentMsg:
		if msg.err != nil {
			l.warn = "could not deliver the answer: " + sanitize.Line(msg.err.Error(), 200)
		} else {
			l.dropAsk(msg.askID)
		}
		return m, nil
	case noteSentMsg:
		if msg.err != nil {
			l.warn = "could not send the note: " + sanitize.Line(msg.err.Error(), 200)
		}
		return m, nil
	case tea.KeyMsg:
		k := msg.String()
		if k == "ctrl+c" {
			switch {
			case l.finish:
				return m, tea.Quit
			case l.confirm:
				m.out.Code = 130
				m.out.Action = "left-while-stopping"
				return m, tea.Quit
			case l.stop:
				// A quick double Ctrl+C is a habit, not a decision: wait a
				// moment, then ask. The event pipe keeps draining meanwhile.
				if m.cfg.Now().Sub(l.stopAt) >= 2*time.Second {
					l.confirm = true
				}
				return m, nil
			default:
				l.stop, l.stopAt = true, m.cfg.Now()
				l.cancel()
				return m, nil
			}
		}
		if l.confirm && (k == "esc" || k == "n") {
			l.confirm = false
			return m, nil
		}
		switch k {
		case "pgup", "pgdown", "home", "end":
			l.sc.key(k, false)
			return m, nil
		}
		if l.finish {
			if l.sc.key(k, true) {
				return m, nil
			}
			if m.setup != nil && m.setup.awaitRun && (k == "enter" || k == "h") {
				m.setup.awaitRun = false
				m.setup.step = setupDone
				m.scr = scrSetup
				return m, nil
			}
			switch k {
			case "h":
				m.scr = scrHome
				return m, nil
			case "s":
				return m.openSandboxes(scrLive)
			case "l":
				if step := l.lastStep(); step != "" {
					m.logv = newLogView(step, stepLogPath(l.runDir(), step))
					m.scr = scrLog
				}
				return m, nil
			}
			switch k {
			case "enter", "r":
				if l.done != nil {
					m.report = newReport(l.done.Report, l.runDir(), l.runsDir, l.exit, l.ended.Sub(l.started))
					m.scr = scrReport
				} else if l.failed != "" && k == "enter" {
					m.logv = newLogView(l.failed, stepLogPath(l.runDir(), l.failed))
					m.scr = scrLog
				}
			case "l":
				if l.failed != "" {
					m.logv = newLogView(l.failed, stepLogPath(l.runDir(), l.failed))
					m.scr = scrLog
				}
			case "q", "esc":
				return m, tea.Quit
			}
			return m, nil
		}
		if nm, cmd, handled := m.keyRun(msg); handled {
			return nm, cmd
		}
		if l.notes && !l.stop {
			if k == "enter" {
				text := strings.TrimSpace(l.note.Value())
				l.note.SetValue("")
				if text == "" {
					return m, nil
				}
				l.log = append(l.log, entry2{kind: "note", text: text})
				eng, dir, id := m.eng, l.runsDir, l.runID
				return m, func() tea.Msg { return noteSentMsg{eng.Note(dir, id, text)} }
			}
			if !l.note.Focused() {
				l.note.Focus()
			}
			var cmd tea.Cmd
			l.note, cmd = l.note.Update(msg)
			return m, cmd
		}
		l.sc.key(k, true)
	case tea.MouseMsg:
		l.sc.mouse(msg)
	}
	return m, nil
}

// keyAsk handles the answer box for the oldest open question.
func (l *liveModel) keyAsk(k tea.KeyMsg) tea.Cmd {
	a := l.asks[0]
	opts := askOptions(a)
	if l.typing || len(opts) == 0 {
		switch k.String() {
		case "esc":
			if len(opts) > 0 {
				l.typing = false
				l.answer.Blur()
			}
			return nil
		case "enter":
			v := strings.TrimSpace(l.answer.Value())
			if v == "" {
				return nil
			}
			return l.send(a, v)
		}
		if !l.answer.Focused() {
			l.answer.Focus()
		}
		var cmd tea.Cmd
		l.answer, cmd = l.answer.Update(k)
		return cmd
	}
	switch k.String() {
	case "up", "k":
		if l.cursor > 0 {
			l.cursor--
		} else if l.cursor < 0 {
			l.cursor = 0
		}
	case "down", "j":
		if l.cursor < len(opts)-1 {
			l.cursor++
		}
	case "enter":
		// Nothing is selected until the user moves: a stray Enter must
		// not answer for them.
		if l.cursor < 0 {
			return nil
		}
		if opts[l.cursor] == typeOwn {
			l.typing = true
			l.answer.Focus()
			return textinput.Blink
		}
		return l.send(a, opts[l.cursor])
	}
	return nil
}

const typeOwn = "\x00type"

func askOptions(a events.Event) []string {
	opts := append([]string{}, a.Choices...)
	if a.AllowText && len(opts) > 0 {
		opts = append(opts, typeOwn)
	}
	return opts
}

func (l *liveModel) send(a events.Event, v string) tea.Cmd {
	sock := events.SocketPath(l.runsDir, a.RunID)
	return func() tea.Msg {
		return answerSentMsg{askID: a.AskID, err: events.Answer(sock, a.AskID, v)}
	}
}

func (l *liveModel) counts() string {
	cand, proven := 0, 0
	for _, s := range l.finds {
		if s == "proven" {
			proven++
		} else {
			cand++
		}
	}
	parts := []string{}
	switch {
	case proven > 0:
		parts = append(parts, fmt.Sprintf("findings %d proven", proven))
	case cand > 0:
		parts = append(parts, fmt.Sprintf("findings %d candidate", cand))
	default:
		parts = append(parts, "findings 0")
	}
	parts = append(parts, fmt.Sprintf("blocked %d", l.blocked))
	return strings.Join(parts, " │ ")
}

func (l *liveModel) askBox(w int) string {
	a := l.asks[0]
	inner := w - 6
	body := []string{sBlue.Render("?") + " " + sBold.Render("The agent asks") + "  " + sDim.Render(a.AskID)}
	for _, q := range wrap(a.Question, inner-2) {
		body = append(body, "  "+sText.Render(q))
	}
	body = append(body, "")
	opts := askOptions(a)
	if l.typing || len(opts) == 0 {
		body = append(body, l.answer.View())
	} else {
		for i, o := range opts {
			label := o
			if o == typeOwn {
				label = "Type an answer…"
			}
			label = truncate(label, inner-4)
			if i == l.cursor {
				body = append(body, sel(inner, "❯ "+label))
			} else {
				body = append(body, "  "+sSoft.Render(label))
			}
		}
	}
	return box(w, strings.Join(body, "\n"))
}

// render turns the log into display lines.
// render returns the display lines. Each entry's lines are cached for the
// current width; only running steps (spinner) are drawn every frame.
func (l *liveModel) render(m model, w int) []string {
	var out []string
	if l.dropped > 0 {
		out = append(out, sDim.Render(fmt.Sprintf("… %d earlier lines not shown", l.dropped)))
	}
	for i := range l.log {
		e := &l.log[i]
		dynamic := e.kind == "step" && e.ev.Status == "start"
		if !dynamic && e.cache != nil && e.cacheW == w {
			out = append(out, e.cache...)
			continue
		}
		lines := l.renderEntry(m, *e, w)
		if !dynamic {
			e.cache, e.cacheW = lines, w
		}
		out = append(out, lines...)
	}
	if l.finish && l.done == nil && l.err != nil {
		out = append(out, "  "+sAmber.Render(sanitize.Line(l.err.Error(), 300)))
	}
	return out
}

func (l *liveModel) renderEntry(m model, e entry2, w int) []string {
	var out []string
	ev := e.ev
	{
		switch e.kind {
		case "step":
			if !l.inlineSteps {
				break
			}
			mark := map[string]string{"ok": sDim.Render("✓"), "fail": sAmber.Render("✗"), "skip": sDim.Render("–")}[ev.Status]
			if ev.Status == "start" {
				mark = sAmber.Render(m.spin())
				if l.finish || l.stop {
					mark = sDim.Render("–")
				}
			}
			line := mark + " " + sText.Render(fmt.Sprintf("%-22s", ev.Name))
			if ev.Detail != "" && ev.Detail != "exit 0" {
				line += " " + sDim.Render(ev.Detail)
			}
			out = append(out, line)
			if e.errLine != "" {
				out = append(out, "    "+sDim.Render("└ ")+sAmber.Render(e.errLine))
			}
		case "agent.message":
			who := ev.Agent
			if who == "" {
				who = l.opts.Agent
			}
			out = append(out, sDim.Render(who))
			for _, t := range wrap(ev.Text, w-2) {
				out = append(out, sSoft.Render(t))
			}
			out = append(out, "")
		case "you":
			head := sDim.Render("you")
			if e.queued {
				head += "  " + sAmber.Render("queued")
			}
			out = append(out, head)
			for _, t := range wrap(e.text, w-2) {
				out = append(out, sText.Render(t))
			}
			out = append(out, "")
		case "agent.tool":
			switch ev.Tool {
			case "thinking":
				out = append(out, sDim.Render("… "+ev.Summary))
			case "failed":
				out = append(out, sAmber.Render("✗ ")+sText.Render(ev.Summary))
			case "permission":
				out = append(out, sDim.Render("› permission ")+sText.Render(ev.Summary))
			default:
				out = append(out, sDim.Render("› ")+sText.Render(ev.Summary))
			}
		case "finding":
			sev := sSoft.Render(ev.Severity)
			if ev.Severity == "critical" {
				sev = sRed.Render(ev.Severity)
			}
			line := sAmber.Render("◆") + " " + sBold.Render(ev.ID) + "  " + sev + "  " + sDim.Render(ev.Title)
			out = append(out, line)
		case "blocked":
			// shown in the side panel
		case "ask":
			if hostAsk(ev.AskID) {
				break
			}
			out = append(out, "  "+sBlue.Render("?")+" "+sDim.Render(ev.AskID+": ")+sText.Render(firstLineOf(ev.Question)))
		case "answer":
			if hostAsk(ev.AskID) && ev.By != "forged" {
				break
			}
			v := "no answer"
			if ev.Value != nil {
				v = *ev.Value
			}
			if ev.By == "forged" {
				out = append(out, "  "+sAmber.Render("! the agent wrote its own answer to "+ev.AskID+"; only answers given here count"))
				break
			}
			out = append(out, "  "+sDim.Render("→ "+ev.AskID+": ")+sSoft.Render(v)+sDim.Render(" ("+ev.By+")"))
		case "done":
			out = append(out, sBold.Render("■ done")+sDim.Render(fmt.Sprintf(" · exit %d", ev.ExitCode)))
		case "note":
			out = append(out, "  "+sBlue.Render("❯")+" "+sSoft.Render(e.text))
		case "stderr":
			out = append(out, "  "+sDim.Render(e.text))
		}
	}
	return out
}

type leftoverMsg struct {
	names []string
	err   error
}

// listSandboxes runs `sbx ls -q`; tests replace it.
var listSandboxes = func(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sbx", "ls", "-q").Output()
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(out)), nil
}

// expectedSandbox is the runner's sandbox name for a run id
// (lab/runner.py: "lab-<recipe>"[:48] + "-HHMMSS"; run id
// "YYYYMMDD-HHMMSS-<recipe>").
func expectedSandbox(runID, recipe string) string {
	if len(runID) < 15 || runID[8] != '-' {
		return ""
	}
	base := "lab-" + recipe
	if len(base) > 48 {
		base = base[:48]
	}
	return strings.TrimRight(base, "-") + "-" + runID[9:15]
}

// checkLeftover asks sbx whether this run's sandbox survived a stopped or
// killed run.
func (l *liveModel) checkLeftover(m model) tea.Cmd {
	want := expectedSandbox(l.runID, recipeName(l.opts.Recipe))
	ctx := m.ctx
	return func() tea.Msg {
		names, err := listSandboxes(ctx)
		if err != nil {
			return leftoverMsg{err: err}
		}
		var left []string
		for _, n := range names {
			if n == want {
				left = append(left, n)
			}
		}
		return leftoverMsg{names: left}
	}
}

func (l *liveModel) leftover() []string {
	if len(l.left) == 0 {
		return nil
	}
	if l.left[0] == "" {
		return []string{"! the sandbox may still exist; check with: sbx ls"}
	}
	var out []string
	for _, n := range l.left {
		out = append(out, "! sandbox "+n+" is still there; remove it with: sbx rm --force "+n)
	}
	return out
}

func firstLineOf(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func recipeName(ref string) string {
	if strings.Contains(ref, "/") && !strings.HasPrefix(ref, "/") {
		return ref[strings.LastIndex(ref, "/")+1:]
	}
	return filepath.Base(ref)
}

func clock(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	s := int(d.Seconds())
	return fmt.Sprintf("%02d:%02d", s/60, s%60)
}

// tail keeps the last lines the engine wrote to stderr, shown when a run
// ends without a report.
type tail struct {
	mu   sync.Mutex
	max  int
	buf  []string
	part string
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.part + string(p)
	parts := strings.Split(s, "\n")
	t.part = parts[len(parts)-1]
	for _, l := range parts[:len(parts)-1] {
		t.buf = append(t.buf, sanitize.Line(l, 500))
		if len(t.buf) > t.max {
			t.buf = t.buf[1:]
		}
	}
	return len(p), nil
}

func (t *tail) lines() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := append([]string{}, t.buf...)
	if t.part != "" {
		out = append(out, sanitize.Line(t.part, 500))
	}
	if len(out) > 15 {
		out = out[len(out)-15:]
	}
	return out
}
