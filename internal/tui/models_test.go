package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// toModelStep walks the flow to the Model question with an empty cache.
func toModelStep(t *testing.T, eng *fakeEngine) (model, tea.Cmd) {
	t.Helper()
	m := testModel(t, eng)
	m.acpAgents = []string{"codex"}
	m = press(t, m, "right", "down", "enter", "enter", "enter", "down", "enter") // path, this folder, codex
	nm, cmd := m.Update(keyMsg("enter"))                                         // ACP
	m = nm.(model)
	nm, probe := m.Update(cmd()) // the cache: nothing known
	return nm.(model), probe
}

func TestModelStepProbesWhenTheCacheIsEmpty(t *testing.T) {
	eng := &fakeEngine{acp: []string{"codex"}, probed: ModelList{Known: true, Current: "gpt-6.2-sol",
		Values: []Model{{"gpt-6.2-sol", "6.2 Sol"}, {"gpt-6-luna", "6 Luna"}}}}
	m, probe := toModelStep(t, eng)
	if probe == nil || m.flow.q.title != "Model" || len(m.flow.q.options) != 2 || m.flow.q.options[0].value != "" || m.flow.q.options[1].value != otherModel {
		t.Fatalf("expected default only while probing: %+v", m.flow.q)
	}
	if !strings.Contains(m.View(), "asking codex for its models… (first time ~1 min)") {
		t.Fatal("no probe spinner")
	}
	golden(t, "agent-models-probing", m)
	nm, _ := m.Update(probe())
	m = nm.(model)
	if len(eng.probes) != 1 || eng.probes[0] != "codex" || len(m.flow.q.options) != 4 || strings.Contains(m.View(), "asking codex") {
		t.Fatalf("probe result not shown: %v %+v", eng.probes, m.flow.q.options)
	}
}

func TestModelStepDefaultWhileProbing(t *testing.T) {
	m, _ := toModelStep(t, &fakeEngine{acp: []string{"codex"}})
	m = press(t, m, "enter") // Agent default, while the probe runs
	if m.flow.q == nil || m.flow.q.title != "Permissions" {
		t.Fatal("default is not selectable while probing")
	}
}

func TestModelProbeFailureShowsTheSignInHint(t *testing.T) {
	hint := "no openai credential stored for codex: sbx run codex <folder>   # sign in with your ChatGPT plan, then quit"
	eng := &fakeEngine{acp: []string{"codex"}, probeErr: hint}
	m, probe := toModelStep(t, eng)
	nm, again := m.Update(probe())
	m = nm.(model)
	if again != nil && len(eng.probes) > 1 {
		t.Fatal("probed twice")
	}
	if len(m.flow.q.options) != 2 || !strings.Contains(m.View(), "no openai credential stored for codex") {
		t.Fatalf("no hint, or not default only: %+v", m.flow.q.options)
	}
	m = press(t, m, "enter")
	if m.flow.q.title != "Permissions" {
		t.Fatal("default does not go on")
	}
}

func TestSetupPrefsProbeModels(t *testing.T) {
	eng := &fakeEngine{probed: ModelList{Known: true, Values: []Model{{"gpt-6-luna", "6 Luna"}}}}
	m := testModel(t, eng)
	m.acpAgents = []string{"codex"}
	m.setup, m.scr = newSetup(Prefs{}), scrSetup
	m.setup.step = setupPrefs
	cmd := m.loadSetupModels()
	nm, probe := m.Update(cmd())
	m = nm.(model)
	if probe == nil || !strings.Contains(m.View(), "asking codex for its models… (first time ~1 min)") {
		t.Fatal("setup does not probe an empty cache")
	}
	nm, _ = m.Update(probe())
	m = nm.(model)
	if len(m.setup.models.Values) != 1 || strings.Contains(m.View(), "first time") {
		t.Fatal("probe result not shown")
	}
}
