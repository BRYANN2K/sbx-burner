package tui

import (
	"strings"
	"testing"
)

func TestModelListDedupesDefault(t *testing.T) {
	mo := modelOptions(ModelList{Current: "default", Values: []Model{{"default", "Default (recommended)"}, {"sonnet", "Sonnet 5.5"}}}, []string{"claude-mythos-5-2", "sonnet"})
	var vals []string
	for _, o := range mo {
		vals = append(vals, o.value)
	}
	if strings.Join(vals, ",") != ",sonnet,claude-mythos-5-2,"+otherModel || mo[0].label != "default (recommended)" {
		t.Fatalf("rows %q", vals)
	}
}

func TestCheckModelID(t *testing.T) {
	listed := ModelList{Values: []Model{{"sonnet", ""}}}
	for _, c := range []struct {
		agent, id   string
		interactive bool
		ok          bool
	}{
		{"claude", "claude-mythos-5-2", false, true}, // set_config_option takes any id
		{"codex", "gpt-7-custom", false, true},       // CODEX_CONFIG
		{"cursor", "gpt-7-custom", false, false},     // only listed ids
		{"cursor", "sonnet", false, true},
		{"claude", "bad id;rm", false, false},
		{"claude", strings.Repeat("a", 81), false, false},
		{"claude", "claude-mythos-5-2", true, true}, // claude --model
		{"opencode", "x", true, false},              // no TUI model flag
	} {
		if err := checkModelID(c.agent, c.id, c.interactive, listed); (err == nil) != c.ok {
			t.Errorf("%s %q interactive=%v: %v", c.agent, c.id, c.interactive, err)
		}
	}
}

func TestOtherModelIsTypedValidatedAndRemembered(t *testing.T) {
	t.Setenv("BURNER_HOME", t.TempDir())
	eng := &fakeEngine{acp: []string{"codex"}, models: ModelList{Known: true, Values: []Model{{"gpt-6.2-sol", "6.2 Sol"}}}}
	m, _ := toModelStep(t, eng)
	for m.flow.q.options[m.flow.cursor].value != otherModel {
		m = press(t, m, "down")
	}
	m = press(t, m, "enter")
	if m.flow.q.title != "Model id" {
		t.Fatalf("no input: %+v", m.flow.q)
	}
	m = typeText(m, "bad id")
	m = press(t, m, "enter")
	if m.flow.q.title != "Model id" || m.flow.err == "" {
		t.Fatal("an invalid id was accepted")
	}
	golden(t, "agent-model-other-invalid", m)
	for range "bad id" {
		m = press(t, m, "backspace")
	}
	m = typeText(m, "gpt-7-custom")
	m = press(t, m, "enter")
	if m.flow.q.title != "Permissions" {
		t.Fatalf("after the id: %q", m.flow.q.title)
	}
	m = press(t, m, "enter", "enter")
	if m.plan == nil || m.plan.opts.Model != "gpt-7-custom" {
		t.Fatal("the typed id is not the run's model")
	}
	p, _ := LoadPrefs()
	if strings.Join(p.CustomModels["codex"], ",") != "gpt-7-custom" {
		t.Fatalf("not remembered: %v", p.CustomModels)
	}
	// Next time it is a row.
	m2, _ := toModelStep(t, eng)
	found := false
	for _, o := range m2.flow.q.options {
		found = found || (o.value == "gpt-7-custom" && o.note == "custom")
	}
	if !found {
		t.Fatal("the remembered id is not offered")
	}
}

func TestSetupOtherModel(t *testing.T) {
	m := testModel(t, &fakeEngine{})
	m.acpAgents = []string{"codex"}
	m.setup, m.scr = newSetup(Prefs{Agent: "claude"}), scrSetup
	m.setup.step, m.setup.field = setupPrefs, 1 // model
	m.setup.models = ModelList{Known: true, Values: []Model{{"default", ""}, {"sonnet", ""}}}
	m = press(t, m, "o")
	if m.setup.other == nil {
		t.Fatal("o did not open the input")
	}
	m = typeText(m, "claude-mythos-5-2")
	golden(t, "setup-prefs-other-model", m)
	m = press(t, m, "enter")
	p := m.setup.prefs
	if p.Model != "claude-mythos-5-2" || strings.Join(p.CustomModels["claude"], ",") != "claude-mythos-5-2" {
		t.Fatalf("prefs %+v", p)
	}
	if v := setupModelValues(m.setup.models, p.CustomModels["claude"], p.Model); strings.Join(v, ",") != ",sonnet,claude-mythos-5-2" {
		t.Fatalf("chips %q", v)
	}
}

func TestPickingDefaultSaysSo(t *testing.T) {
	t.Setenv("BURNER_HOME", t.TempDir())
	eng := &fakeEngine{acp: []string{"codex"}, models: ModelList{Known: true, Values: []Model{{"gpt-6.2-sol", "6.2 Sol"}}}}
	m, _ := toModelStep(t, eng)
	m = press(t, m, "enter", "enter", "enter") // default, auto, no notes
	if m.plan == nil || m.plan.opts.Model != "default" || !strings.Contains(strings.Join(m.plan.opts.Args(), " "), "--model=default") {
		t.Fatalf("plan %+v", m.plan)
	}
	if p, _ := LoadPrefs(); len(p.CustomModels["codex"]) != 0 {
		t.Fatal("default was remembered as a custom model")
	}
}
