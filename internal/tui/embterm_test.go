package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"strings"
	"testing"
	"time"
)

// A command run for the user shows its output inside burner's panel and
// keeps it readable after it exits.
func TestEmbeddedTerminalShowsOutputAndStays(t *testing.T) {
	term, _, err := startTerm(openTermMsg{title: "probe", argv: []string{"sh", "-c", "printf 'hello from sbx'"}}, 120, 30)
	if err != nil {
		t.Fatal(err)
	}
	var exitErr error
	deadline := time.After(5 * time.Second)
	for done := false; !done; {
		select {
		case <-term.update:
		case exitErr = <-term.exited:
			done = true
		case <-deadline:
			t.Fatal("command did not finish")
		}
	}
	term.ended, term.exitErr = true, exitErr
	v := term.view(120, 30)
	if !strings.Contains(v, "hello from sbx") || !strings.Contains(v, "enter close") {
		t.Fatalf("view:\n%s", v)
	}
}

// A quick esc esc reaches burner as alt+esc; it must leave the panel even
// when the command never exits by itself.
func TestEmbeddedTerminalLeaveKeyCloses(t *testing.T) {
	m := model{w: 120, h: 30}
	term, _, err := startTerm(openTermMsg{title: "probe", argv: []string{"sh", "-c", "sleep 30"}}, 120, 30)
	if err != nil {
		t.Fatal(err)
	}
	m.term = term
	m, _, _ = m.updateTerm(tea.KeyMsg{Type: tea.KeyEsc, Alt: true})
	select {
	case err := <-term.exited:
		m, _, _ = m.updateTerm(termExitMsg{term, err})
	case <-time.After(5 * time.Second):
		t.Fatal("the command was not stopped")
	}
	if m.term != nil {
		t.Fatal("the panel did not close")
	}
}
