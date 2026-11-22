package tui

import (
	"strings"
	"testing"

	"github.com/BRYANN2K/sbx-burner/internal/engine"
)

func TestScopeFormEveryTechniqueRowIsReachable(t *testing.T) {
	eng := formEngine()
	m := testModel(t, eng)
	m.form = newScopeForm(eng.scopeOut(engine.RunOptions{}, "", true).Scope, "web-recon", "", m.cfg.Now())
	m.scr = scrScopeForm
	f := m.form
	for formFields[f.field] != "days" {
		m = press(t, m, "down")
	}
	m = press(t, m, "down") // into the techniques, first row
	all := append(append([]techRow{}, f.techs...), f.risky...)
	for i := range all {
		if formFields[f.field] != "techs" || f.tcur != i {
			t.Fatalf("row %d: field %s cursor %d", i, formFields[f.field], f.tcur)
		}
		before := append(append([]techRow{}, f.techs...), f.risky...)[i].on
		m = press(t, m, "space")
		after := append(append([]techRow{}, f.techs...), f.risky...)[i].on
		if before == after {
			t.Fatalf("space did not toggle row %d", i)
		}
		if !strings.Contains(m.View(), "❯ [") {
			t.Fatal("the focused row has no cursor")
		}
		m = press(t, m, "down")
	}
	if formFields[f.field] != "out" {
		t.Fatalf("down after the last row went to %s, want out", formFields[f.field])
	}
	m = press(t, m, "up")
	if formFields[f.field] != "techs" || f.tcur != len(all)-1 {
		t.Fatal("up from the next field does not land on the last row")
	}
	for formFields[f.field] == "techs" {
		m = press(t, m, "down")
	}
	m = press(t, m, "up")
	m = press(t, m, "a")
	for _, r := range f.techs {
		if !r.on {
			t.Fatal("a did not turn every normal technique on")
		}
	}
	m = press(t, m, "n")
	for _, r := range f.techs {
		if r.on {
			t.Fatal("n did not turn every normal technique off")
		}
	}
	if !f.risky[len(f.risky)-1].on {
		t.Fatal("a/n touched the risky group")
	}
}

func TestScopeFormFitsAShortTerminal(t *testing.T) {
	eng := formEngine()
	m := testModel(t, eng)
	m.w, m.h = 100, 30
	m.form = newScopeForm(eng.scopeOut(engine.RunOptions{}, "", true).Scope, "web-recon", "", m.cfg.Now())
	m.scr = scrScopeForm
	for i := 0; i < 20; i++ {
		m = press(t, m, "down")
		if !strings.Contains(m.View(), "❯ ") {
			t.Fatalf("step %d: the focused line scrolled out of view", i)
		}
	}
	golden(t, "scope-form-short", m)
}
