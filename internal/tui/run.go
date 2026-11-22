package tui

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"gopkg.in/yaml.v3"

	"github.com/BRYANN2K/sbx-burner/internal/events"
	"github.com/BRYANN2K/sbx-burner/internal/sanitize"
)

// approvalCard is the credential binding a mixin kit needs before the run
// can start (the engine's binding preflight names it).
type approvalCard struct {
	agent string
	hosts []string
	err   string
	busy  bool
}

var bindingHostRE = regexp.MustCompile(`^\s+- ([A-Za-z0-9.-]+(?::\d+)?)\s*$`)

// approvalFromPlan reads the agent and the missing domains from a plan the
// engine refused for a missing credential binding.
func approvalFromPlan(text string) *approvalCard {
	agent := approveAgent(text)
	if agent == "" {
		return nil
	}
	c := &approvalCard{agent: agent}
	in := false
	for _, l := range strings.Split(text, "\n") {
		if strings.Contains(l, "bindings:") {
			in = true
			continue
		}
		if in {
			if m := bindingHostRE.FindStringSubmatch(l); m != nil {
				c.hosts = append(c.hosts, sanitize.Line(m[1], 120))
			}
		}
	}
	return c
}

// planSteps lists the step names of the engine's dry run, policy-close
// steps folded into one.
var planStepRE = regexp.MustCompile(`^\s+\d+\. ([a-z0-9][a-z0-9:._-]*)`)

func planSteps(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, l := range strings.Split(text, "\n") {
		m := planStepRE.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		name := strings.TrimSuffix(m[1], ":")
		if strings.HasPrefix(name, "policy-close:") {
			name = "policy-close"
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// planField reads "  key:   value" from the dry run header.
func planField(text, key string) string {
	for _, l := range strings.Split(text, "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, key+":") {
			return strings.TrimSpace(strings.TrimPrefix(t, key+":"))
		}
	}
	return ""
}

// readScope loads the hosts and network mode of a scope file.
func readScope(path string) ([]string, string) {
	raw, err := readCapped(path)
	if err != nil {
		return nil, ""
	}
	var s struct {
		Targets []struct {
			Hosts []string `yaml:"hosts"`
		} `yaml:"targets"`
		Network struct {
			Mode string `yaml:"mode"`
		} `yaml:"network"`
	}
	if yaml.Unmarshal(raw, &s) != nil {
		return nil, ""
	}
	var hosts []string
	for _, t := range s.Targets {
		for _, h := range t.Hosts {
			hosts = append(hosts, sanitize.Line(h, 200))
		}
	}
	mode := s.Network.Mode
	if mode == "" {
		mode = "strict"
	}
	return hosts, sanitize.Line(mode, 20)
}

func (l *liveModel) modeName() string {
	switch {
	case l.opts.ACP:
		return "ACP"
	case l.opts.Interactive:
		return "interactive"
	}
	return "headless"
}

func (l *liveModel) sandboxName() string {
	if n := events.SandboxForRun(l.runID); n != "" {
		return n
	}
	return planField(l.planText, "sandbox")
}

// firstAsk is the oldest question still open, if any.
func (l *liveModel) firstAsk() (events.Event, bool) {
	if len(l.asks) == 0 {
		return events.Event{}, false
	}
	return l.asks[0], true
}

// hostAsk: questions burner shows as cards (permissions, turn ends, the
// agent's own TUI), not as lines in the conversation.
func hostAsk(id string) bool {
	return strings.HasPrefix(id, "acp-perm-") || strings.HasPrefix(id, "acp-turn-") || id == events.InteractiveAsk
}

func isPermAsk(a events.Event) bool { return strings.HasPrefix(a.AskID, "acp-perm-") }
func isTurnAsk(a events.Event) bool { return strings.HasPrefix(a.AskID, "acp-turn-") }

// pickLabel returns the offered choice of a permission ask whose kind is
// kind ("allow_once", "reject_once"); allow_always is never picked.
func pickLabel(a events.Event, kind string) (string, bool) {
	for _, c := range a.Choices {
		if strings.HasSuffix(c, "("+kind+")") {
			return c, true
		}
	}
	return "", false
}

type handoffDoneMsg struct {
	ask events.Event
	err error
}

type agentTUIDoneMsg struct{ err error }

type replanMsg struct {
	text string
	code int
	err  error
}

// onAsk reacts to a new question: the agent-tui handoff runs the agent's own
// TUI; a turn boundary sends the queued messages.
func (m model) onAsk(e events.Event) tea.Cmd {
	l := m.live
	switch {
	case e.AskID == events.InteractiveAsk:
		if l.handoff == nil {
			return nil
		}
		argv := l.handoff
		l.log = append(l.log, entry2{kind: "note", text: l.opts.Agent + "'s own TUI is open"})
		return termCmd("Agent TUI", argv, func(err error) tea.Msg { return handoffDoneMsg{ask: e, err: err} })
	case isTurnAsk(e) && len(l.queue) > 0:
		return l.flushQueue(e)
	}
	return nil
}

// flushQueue sends every queued message as the next turn's prompt.
func (l *liveModel) flushQueue(turn events.Event) tea.Cmd {
	var parts []string
	for _, i := range l.queue {
		if i < len(l.log) {
			parts = append(parts, l.log[i].text)
			l.log[i].queued = false
			l.log[i].cache = nil
		}
	}
	l.queue = nil
	return l.send(turn, strings.Join(parts, "\n\n"))
}

// sendChat sends a message now when the agent waits at a turn boundary,
// else queues it for the next one (ACP takes one prompt per turn).
func (m model) sendChat(text string) tea.Cmd {
	l := m.live
	l.log = append(l.log, entry2{kind: "you", text: sanitize.Text(text, 8192), queued: true})
	l.queue = append(l.queue, len(l.log)-1)
	if a, ok := l.firstAsk(); ok && isTurnAsk(a) {
		return l.flushQueue(a)
	}
	return nil
}

// keyRun handles the run screen's keys while the run is going. It returns
// handled=false for keys the caller handles (scroll, stop).
func (m model) keyRun(k tea.KeyMsg) (model, tea.Cmd, bool) {
	l := m.live
	key := k.String()
	if l.approval != nil {
		switch key {
		case "a":
			if !l.approval.busy {
				l.approval.busy, l.approval.err = true, ""
				return m, approveCmd(l.approval.agent), true
			}
		case "esc":
			m.scr = scrPlan
		}
		return m, nil, true
	}
	if l.chatOn {
		switch key {
		case "esc":
			l.chatOn = false
			l.chat.Blur()
			return m, nil, true
		case "enter":
			text := strings.TrimSpace(l.chat.Value())
			l.chat.SetValue("")
			l.chatOn = false
			l.chat.Blur()
			if text == "" {
				return m, nil, true
			}
			return m, m.sendChat(text), true
		}
		var cmd tea.Cmd
		l.chat, cmd = l.chat.Update(k)
		return m, cmd, true
	}
	if a, ok := l.firstAsk(); ok && !l.stop {
		switch {
		case isPermAsk(a):
			switch key {
			case "a":
				if v, ok := pickLabel(a, "allow_once"); ok {
					return m, l.send(a, v), true
				}
			case "r":
				if v, ok := pickLabel(a, "reject_once"); ok {
					return m, l.send(a, v), true
				}
			case "m":
				cmd := tea.Cmd(nil)
				if v, ok := pickLabel(a, "reject_once"); ok {
					cmd = l.send(a, v)
				}
				l.chatOn = true
				return m, tea.Batch(cmd, l.chat.Focus()), true
			}
			return m, nil, true
		case isTurnAsk(a):
			switch key {
			case "f":
				return m, l.send(a, "Finish"), true
			case "enter":
				l.chatOn = true
				return m, l.chat.Focus(), true
			}
		case a.AskID != events.InteractiveAsk:
			return m, l.keyAsk(k), true
		}
	}
	switch key {
	case "enter":
		if l.opts.ACP {
			l.chatOn = true
			return m, l.chat.Focus(), true
		}
	case "o":
		l.toggleAction()
		return m, nil, true
	case "O":
		l.toggleAll()
		return m, nil, true
	case "l":
		if step := l.lastStep(); step != "" {
			m.logv = newLogView(step, stepLogPath(l.runDir(), step))
			m.scr = scrLog
		}
		return m, nil, true
	}
	return m, nil, false
}

// lastStep is the failed step, else the last step that finished.
func (l *liveModel) lastStep() string {
	if l.failed != "" {
		return l.failed
	}
	for i := len(l.log) - 1; i >= 0; i-- {
		if e := l.log[i]; e.kind == "step" && e.ev.Status != "start" {
			return e.ev.Name
		}
	}
	return ""
}

// viewLive draws the run: steps (sandbox pinned at the bottom),
// conversation with the chat input, and the side panel.
func (m model) viewLive() string {
	l := m.live
	w, h := m.w, m.h
	var b strings.Builder

	title := sBold.Render(recipeName(l.opts.Recipe))
	model := l.opts.Model
	if model == "" {
		model = "default"
	}
	meta := []string{l.opts.Agent}
	if l.opts.ACP || l.opts.Interactive {
		meta = append(meta, model)
	}
	meta = append(meta, l.modeName())
	if t := targetLabelOf(l.opts); t != "" {
		meta = append(meta, t)
	}
	title += sDim.Render(" · " + strings.Join(meta, " · "))
	waiting := l.approval != nil
	if a, ok := l.firstAsk(); ok && (isPermAsk(a) || isTurnAsk(a) || a.AskID != events.InteractiveAsk) {
		waiting = true
	}
	var right string
	switch {
	case l.finish && l.done != nil:
		right = sBold.Render("■ done") + sDim.Render(fmt.Sprintf(" · exit %d · %s", l.exit, clock(l.ended.Sub(l.started))))
	case l.finish:
		right = sAmber.Render(fmt.Sprintf("stopped · exit %d", l.exit))
	case l.stop:
		right = sAmber.Render(m.spin()) + sDim.Render(" stopping, destroying the sandbox…")
	case waiting:
		right = sAmber.Render("waiting for you")
	default:
		right = sAmber.Render(m.spin()) + sDim.Render(" running "+clock(m.cfg.Now().Sub(l.started)))
	}
	b.WriteString(header(w, title, right) + "\n")

	// Bottom: chat input, notices, keys.
	var bottom []string
	if l.opts.ACP && !l.finish && l.approval == nil {
		l.chat.Width = max(10, w-8)
		in := l.chat.View()
		bottom = append(bottom, sBox.Width(w-2).Render(in))
	}
	if l.confirm && !l.finish {
		bottom = append(bottom, box(w, sAmber.Render("Leave without waiting?")+"  "+sSoft.Render("The runner is destroying the sandbox; if you leave now it may remain.")))
	}
	for _, line := range l.leftover() {
		bottom = append(bottom, "  "+sAmber.Render(line))
	}
	if l.warn != "" {
		bottom = append(bottom, "  "+sAmber.Render("! "+l.warn))
	}
	bottom = append(bottom, l.runHints())
	bottomStr := strings.Join(bottom, "\n")
	bodyH := max(6, h-1-lipgloss.Height(bottomStr))

	stepsW, sideW := 30, 34
	showSteps, showSide := w >= 90, w >= 120
	if !showSide {
		sideW = 0
	}
	if !showSteps {
		stepsW = 0
	}
	if l.inlineSteps == showSteps {
		l.inlineSteps = !showSteps
		for i := range l.log {
			l.log[i].cache = nil
		}
	}
	chatW := w - stepsW - sideW
	convo := l.render(m, chatW-4)
	convo = append(convo, l.cards(m, chatW-4)...)
	conv := l.sc.view(convo, chatW-4, bodyH-2)

	var cols []string
	if showSteps {
		cols = append(cols, col(stepsW, bodyH, l.stepsColumn(m, stepsW-4, bodyH-2), "left"))
	}
	pos := "right"
	if showSteps && showSide {
		pos = "mid"
	} else if showSteps {
		pos = "right"
	} else if showSide {
		pos = "left"
	}
	if !showSteps && !showSide {
		cols = append(cols, box(chatW, strings.Join(conv, "\n")))
	} else {
		cols = append(cols, col(chatW, bodyH, strings.Join(conv, "\n"), pos))
	}
	if showSide {
		cols = append(cols, col(sideW, bodyH, l.sideColumn(sideW-4), "right"))
	}
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, cols...) + "\n")
	b.WriteString(bottomStr)
	return b.String()
}

func (l *liveModel) runHints() string {
	a, ask := l.firstAsk()
	switch {
	case l.approval != nil:
		return hints("a", "approve", "esc", "cancel")
	case l.chatOn:
		return hints("enter", "send", "esc", "leave the input")
	case l.confirm:
		return hints("ctrl+c", "leave now", "esc", "keep waiting")
	case l.finish && l.done != nil:
		return hints("enter", "report", "l", "log", "h", "home", "s", "sandboxes", "q", "quit")
	case l.finish:
		k := []string{"h", "home", "q", "quit"}
		if l.failed != "" {
			k = append([]string{"enter", "full log"}, k...)
		}
		return hints(k...)
	case l.stop:
		return hints("pgup pgdn", "scroll", "ctrl+c", "leave (asks first)")
	case ask && isPermAsk(a):
		return hints("a", "allow once", "r", "reject", "m", "message")
	case ask && isTurnAsk(a):
		return hints("enter", "message", "f", "finish")
	case ask && a.AskID != events.InteractiveAsk:
		return hints("↑↓", "choose", "enter", "answer")
	}
	k := []string{}
	if l.opts.ACP {
		k = append(k, "enter", "send")
	}
	if n, _, _ := l.activity(); n > 0 {
		k = append(k, "o", "open / close action", "O", "open all")
	}
	return hints(append(k, "l", "log", "ctrl+c", "stop")...)
}

// stepsColumn: STEPS, then the SANDBOX block pinned at the bottom.
func (l *liveModel) stepsColumn(m model, w, h int) string {
	lines := []string{sDim.Render("STEPS")}
	if l.approval != nil {
		lines = append(lines, sAmber.Render("◇ approval")+strings.Repeat(" ", max(1, w-18))+sAmber.Render("waiting"))
	}
	seen := map[string]bool{}
	for _, e := range l.log {
		if e.kind != "step" {
			continue
		}
		ev := e.ev
		seen[ev.Name] = true
		mark := map[string]string{"ok": sDim.Render("✓"), "fail": sAmber.Render("✗"), "skip": sDim.Render("–")}[ev.Status]
		if ev.Status == "start" {
			mark = sAmber.Render(m.spin())
			if l.finish || l.stop {
				mark = sDim.Render("–")
			}
		}
		lines = append(lines, mark+" "+sText.Render(truncate(ev.Name, w-2)))
		if e.errLine != "" {
			for _, t := range wrap(e.errLine, w-2) {
				lines = append(lines, "  "+sAmber.Render(t))
			}
		}
	}
	if !l.finish {
		for _, s := range planSteps(l.planText) {
			if !seen[s] {
				lines = append(lines, "  "+sFaint.Render(truncate(s, w-2)))
			}
		}
	}
	scope := "no scope"
	if l.opts.Scope != "" {
		scope = l.scopeMode + " scope"
	}
	box := []string{sDim.Render("SANDBOX"), sDim.Render(truncate(l.sandboxName(), w))}
	if img := planField(l.planText, "image"); img != "" {
		box = append(box, sDim.Render(truncate(img+" · "+scope, w)))
	} else {
		box = append(box, sDim.Render(scope))
	}
	room := h - len(box)
	if len(lines) > room {
		lines = lines[len(lines)-room:]
	}
	for len(lines) < room {
		lines = append(lines, "")
	}
	return strings.Join(append(lines, box...), "\n")
}

// sideColumn: findings, network, permissions.
func (l *liveModel) sideColumn(w int) string {
	kv := func(k, v string, vs lipgloss.Style) string {
		k = truncate(k, w-lipgloss.Width(v)-1)
		return k + strings.Repeat(" ", max(1, w-lipgloss.Width(k)-lipgloss.Width(v))) + vs.Render(v)
	}
	lines := []string{sDim.Render("FINDINGS")}
	n := 0
	shown := map[string]bool{}
	for i := len(l.log) - 1; i >= 0; i-- { // newest status wins
		e := l.log[i]
		if e.kind != "finding" || shown[e.ev.ID] {
			continue
		}
		shown[e.ev.ID] = true
		n++
		sev := sAmber
		if e.ev.Severity == "critical" || e.ev.Severity == "high" {
			sev = sRed
		}
		lines = append(lines, kv(sAmber.Render("◆ ")+e.ev.ID, e.ev.Severity, sev))
	}
	if n == 0 {
		lines = append(lines, sFaint.Render("none yet"))
	}
	lines = append(lines, "", sDim.Render("NETWORK"))
	scoped := map[string]bool{}
	for _, hst := range l.scopeHost {
		scoped[hst] = true
		lines = append(lines, kv(hst, "in scope", sDim))
	}
	for _, hst := range strings.Split(planField(l.planText, "allow"), ",") {
		hst = strings.TrimSpace(hst)
		if hst == "" || hst == "nothing" || scoped[hst] {
			continue
		}
		lines = append(lines, kv(hst, "allowed", sDim))
	}
	for _, e := range l.log {
		if e.kind == "blocked" {
			lines = append(lines, sFaint.Render(kv("⊘ "+e.ev.Host, "blocked", sFaint)))
		}
	}
	if n, done, failed := l.activity(); n > 0 || l.opts.ACP {
		lines = append(lines, "", sDim.Render("ACTIVITY"))
		lines = append(lines, kv("actions", fmt.Sprintf("%d · %d done", n, done), sDim))
		fs := sDim
		if failed > 0 {
			fs = sAmber
		}
		lines = append(lines, kv("failed", fmt.Sprint(failed), fs))
	}
	if l.opts.ACP {
		lines = append(lines, "", sDim.Render("PERMISSIONS"))
		lines = append(lines, kv("auto-allowed", fmt.Sprintf("%d · logged", l.autoAllow), sDim))
		waiting := false
		if a, ok := l.firstAsk(); ok && isPermAsk(a) {
			waiting = true
		}
		if waiting {
			lines = append(lines, kv("asked you", "1 waiting", sAmber))
		} else {
			lines = append(lines, kv("asked you", fmt.Sprint(l.asked), sDim))
		}
	}
	return strings.Join(lines, "\n")
}

// cards are the inline prompts at the end of the conversation.
func (l *liveModel) cards(m model, w int) []string {
	card := func(lines ...string) []string {
		return append(strings.Split(sBox.Width(w-2).Render(strings.Join(lines, "\n")), "\n"), "")
	}
	if c := l.approval; c != nil {
		svc := map[string]string{"codex": "OpenAI", "claude": "Anthropic"}[c.agent]
		title := "Approve your " + c.agent + " login for burner's " + c.agent + " kit"
		if svc != "" {
			title = "Approve your " + svc + " login for burner's " + c.agent + " kit"
		}
		body := []string{sBold.Render(title), ""}
		for _, hst := range c.hosts {
			body = append(body, "  "+sSoft.Render(hst))
		}
		if c.busy {
			body = append(body, "", sAmber.Render(m.spin())+" "+sDim.Render("sbx approval"))
		}
		if c.err != "" {
			body = append(body, "", sAmber.Render(c.err))
		}
		body = append(body, "", sSoft.Render("a")+" "+sDim.Render("approve in sbx")+"   "+sSoft.Render("esc")+" "+sDim.Render("cancel"))
		return card(body...)
	}
	if a, ok := l.firstAsk(); ok && !l.finish {
		switch {
		case a.AskID == events.InteractiveAsk:
		case isPermAsk(a):
			what := strings.TrimPrefix(a.Question, "The agent asks permission: ")
			body := []string{sBold.Render(l.opts.Agent + " wants to run"), ""}
			for _, t := range wrap(what, w-4) {
				body = append(body, sSoft.Render(t))
			}
			keys := []string{}
			if _, ok := pickLabel(a, "allow_once"); ok {
				keys = append(keys, sSoft.Render("a")+" "+sDim.Render("allow once"))
			}
			if _, ok := pickLabel(a, "reject_once"); ok {
				keys = append(keys, sSoft.Render("r")+" "+sDim.Render("reject"), sSoft.Render("m")+" "+sDim.Render("message"))
			}
			body = append(body, "", strings.Join(keys, "   "))
			return card(body...)
		case isTurnAsk(a):
			return card(sBold.Render(l.opts.Agent+" ended its turn"), "",
				sSoft.Render("enter")+" "+sDim.Render("message")+"   "+sSoft.Render("f")+" "+sDim.Render("finish"))
		default:
			return strings.Split(l.askBox(w), "\n")
		}
	}
	if l.finish && l.done != nil {
		n := 0
		for _, e := range l.log {
			if e.kind == "finding" && e.ev.Status == "proven" {
				n++
			}
		}
		word := "findings"
		if n == 1 {
			word = "finding"
		}
		return card(sBold.Render(fmt.Sprintf("%d %s · report written", n, word)), "",
			sSoft.Render("enter")+" "+sDim.Render("report")+"   "+sSoft.Render("h")+" "+sDim.Render("home"))
	}
	return nil
}

// initRun fills what the run screen needs from the plan and the scope.
func (l *liveModel) initRun(planText string, tui []string) {
	l.planText = planText
	l.tuiCmd = tui
	if l.opts.Scope != "" {
		l.scopeHost, l.scopeMode = readScope(l.opts.Scope)
	}
}

var _ = os.Getenv
