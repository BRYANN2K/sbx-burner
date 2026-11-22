package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/BRYANN2K/sbx-burner/internal/doctor"
)

// bareMac is doctor.Check on a Mac with nothing installed; withBrew is the
// same machine once Homebrew exists.
func bareMac(withBrew bool) []doctor.Result {
	exists := func(p string) bool { return withBrew && p == "/opt/homebrew/bin/brew" }
	res := doctor.Check(context.Background(), doctor.Options{
		GOOS: "darwin", Exists: exists, Agents: []string{"claude", "codex"},
		LookPath: func(string) (string, error) { return "", errors.New("missing") },
		Run:      func(context.Context, string, ...string) (string, error) { return "", errors.New("not run") },
	})
	return append(res, doctor.Result{ID: "disk", Title: "Free disk", Level: doctor.Warn, Detail: "6 GB free",
		Actions: []doctor.Action{{Label: "free space", Note: "burner needs about 10 GB for sandbox images and recipe kits"}}})
}

func bareSetup(t *testing.T, withBrew bool) model {
	t.Helper()
	m := testModel(t, &fakeEngine{})
	m.setup, m.scr = newSetup(Prefs{}), scrSetup
	m.checks = bareMac(withBrew)
	return m
}

func TestSetupMachineNothingInstalled(t *testing.T) {
	m := bareSetup(t, false)
	golden(t, "setup-machine-bare", m)
	m.setup.cursor = 2 // the runtime line: three choices
	golden(t, "setup-machine-bare-runtime", m)
}

// termArgv runs cmd and returns the embedded terminal it opens.
func termArgv(t *testing.T, cmd tea.Cmd) openTermMsg {
	t.Helper()
	if cmd == nil {
		t.Fatal("no command")
	}
	o, ok := cmd().(openTermMsg)
	if !ok {
		t.Fatal("the command does not run in burner's terminal")
	}
	return o
}

func TestEveryMachineActionRunsInTheTerminalOnEnter(t *testing.T) {
	for _, withBrew := range []bool{false, true} {
		m := bareSetup(t, withBrew)
		rows := m.machineRows()
		ran := 0
		for i, r := range rows {
			for chip, a := range r.Actions {
				m.setup.cursor, m.setup.chip, m.setup.busy = i, chip, false
				nm, cmd := m.Update(keyMsg("enter"))
				if len(a.Argv) == 0 {
					if cmd != nil {
						t.Fatalf("%s/%s has no command but enter ran one", r.ID, a.Label)
					}
					continue
				}
				o := termArgv(t, cmd)
				if strings.Join(o.argv, "\x00") != strings.Join(a.Argv, "\x00") || o.title != machineTitle(r.ID) {
					t.Fatalf("%s/%s: %q %q", r.ID, a.Label, o.title, o.argv)
				}
				if !nm.(model).setup.busy {
					t.Fatal("not busy while the command runs")
				}
				ran++
			}
		}
		if withBrew && ran < 8 || !withBrew && ran != 1 { // before Homebrew only its installer runs
			t.Fatalf("brew=%v: %d actions ran", withBrew, ran)
		}
	}
}

func TestMachineStepRunsNothingWithoutEnter(t *testing.T) {
	m := bareSetup(t, true)
	for _, k := range []string{"down", "down", "right", "left", "up", "j", "k", "x", "space", "tab"} {
		nm, cmd := m.Update(keyMsg(k))
		m = nm.(model)
		if cmd != nil {
			t.Fatalf("%s ran a command", k)
		}
	}
	// enter on a green line does nothing.
	for i, r := range m.machineRows() {
		if r.Level == doctor.OK {
			m.setup.cursor = i
			if _, cmd := m.Update(keyMsg("enter")); cmd != nil {
				t.Fatalf("enter on green %s ran a command", r.ID)
			}
		}
	}
}

func TestRuntimeChoiceAndNextRedLine(t *testing.T) {
	m := bareSetup(t, true)
	if r := m.machineRows()[m.setup.machineCursor(m.machineRows())]; r.ID != "sbx" {
		t.Fatalf("opens on %s, want the first red line (sbx)", r.ID)
	}
	m.setup.cursor = 2
	m = press(t, m, "right")
	_, cmd := m.Update(keyMsg("enter"))
	if o := termArgv(t, cmd); !strings.Contains(o.argv[2], "--cask docker-desktop") {
		t.Fatalf("chip Docker Desktop ran %q", o.argv)
	}
	// The install ends: checks run again, the cursor goes to the next red line.
	m.setup.busy, m.setup.advance = false, true
	nm, cmd := m.Update(setupExecDoneMsg{what: "Container runtime"})
	m = nm.(model)
	if cmd == nil {
		t.Fatal("the checks did not run again")
	}
	fixed := bareMac(true)
	for i := range fixed {
		if fixed[i].ID == "runtime" || fixed[i].ID == "sbx" || fixed[i].ID == "brew" {
			fixed[i].Level, fixed[i].Actions = doctor.OK, nil
		}
	}
	nm, _ = m.Update(checksMsg(fixed))
	m = nm.(model)
	if r := m.machineRows()[m.setup.cursor]; r.ID != "buildx" {
		t.Fatalf("cursor on %s, want buildx", r.ID)
	}
}

func TestDoctorRunsTheSameActions(t *testing.T) {
	m := testModel(t, &fakeEngine{})
	m.checks = bareMac(true)
	m = press(t, m, "d")
	for m.checks[m.doc.cursor].ID != "runtime" {
		m = press(t, m, "down")
	}
	if !strings.Contains(m.View(), "colima  $ brew install colima docker && colima start") {
		t.Fatal("doctor does not show the runtime action")
	}
	m = press(t, m, "right", "right")
	_, cmd := m.Update(keyMsg("a"))
	if o := termArgv(t, cmd); !strings.Contains(o.argv[2], "brew\" install container && container system start") {
		t.Fatalf("doctor ran %q", o.argv)
	}
}

func TestActionLineReadsAsTyped(t *testing.T) {
	got := actionLine(doctor.Action{Argv: []string{"/bin/sh", "-c", `brew='/opt/homebrew/bin/brew'; "$brew" install docker-buildx && ln -sfn "$("$brew" --prefix)/bin/docker-buildx" x`}})
	if got != `brew install docker-buildx && ln -sfn "$(brew --prefix)/bin/docker-buildx" x` {
		t.Fatal(got)
	}
	if got := actionLine(doctor.Action{Argv: []string{"/opt/homebrew/bin/brew", "install", "git"}}); got != "brew install git" {
		t.Fatal(got)
	}
}
