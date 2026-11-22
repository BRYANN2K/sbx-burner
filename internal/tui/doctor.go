package tui

import (
	"fmt"
	"os"
	"strings"

	"github.com/atotto/clipboard"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/BRYANN2K/sbx-burner/internal/catalog"
	"github.com/BRYANN2K/sbx-burner/internal/doctor"
	"github.com/BRYANN2K/sbx-burner/internal/scaffold"
)

type doctorModel struct {
	cursor   int
	checking bool
	msg      string
	policy   bool // confirming sbx policy init deny-all
}

// copyText is replaced in tests.
var copyText = clipboard.WriteAll

func (m model) updateDoctor(msg tea.Msg) (tea.Model, tea.Cmd) {
	d := &m.doc
	if e, ok := msg.(setupExecDoneMsg); ok {
		if e.err != nil {
			d.msg = e.what + ": " + e.err.Error()
		}
		m.checking, d.checking = true, true
		return m, m.runChecks()
	}
	if _, ok := msg.(approveDoneMsg); ok {
		// Check every line again: the approval may now be recorded.
		m.checking, d.checking = true, true
		return m, m.runChecks()
	}
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	d.msg = ""
	if d.policy {
		switch k.String() {
		case "enter":
			d.policy = false
			return m, execSetup("sbx policy init", strings.Fields(doctor.PolicyInitCommand))
		case "esc":
			d.policy = false
		}
		return m, nil
	}
	switch k.String() {
	case "u":
		if m.newer != "" {
			return m.updateOutcome()
		}
	case "a":
		if d.cursor < len(m.checks) {
			c := m.checks[d.cursor]
			switch {
			case c.ID == "policy" && c.Level != doctor.OK:
				d.policy = true
				return m, nil
			case strings.HasPrefix(c.ID, "agent-") && c.Level != doctor.OK:
				a := strings.TrimPrefix(c.ID, "agent-")
				if argv := connectCommand(a); len(argv) > 0 {
					_ = os.MkdirAll(sampleDir(), 0o755)
					return m, execSetup("connect "+a, argv)
				}
			}
		}
		if d.cursor < len(m.checks) {
			c := m.checks[d.cursor]
			if strings.HasPrefix(c.ID, "approval-") && c.Level != doctor.OK {
				return m, approveCmd(strings.TrimPrefix(c.ID, "approval-"))
			}
		}
	case "up", "k":
		if d.cursor > 0 {
			d.cursor--
		}
	case "down", "j":
		if d.cursor < len(m.checks)-1 {
			d.cursor++
		}
	case "c":
		if d.cursor < len(m.checks) && m.checks[d.cursor].Fix != "" {
			if err := copyText(m.checks[d.cursor].Fix); err != nil {
				d.msg = "could not copy: " + err.Error()
			} else {
				d.msg = "copied: " + m.checks[d.cursor].Fix
			}
		} else {
			d.msg = "nothing to fix here"
		}
	case "r":
		if !m.checking {
			m.checking, d.checking = true, true
			return m, m.runChecks()
		}
	case "esc", "enter":
		m.scr = scrHome
	case "q":
		return m, tea.Quit
	}
	return m, nil
}

func (m model) viewDoctor() string {
	d := m.doc
	w := m.w
	var b strings.Builder
	b.WriteString(sBold.Render("Doctor") + "\n\n")
	var body []string
	if m.checking {
		body = append(body, sAmber.Render(m.spin())+" "+sDim.Render("checking sbx, runtime, credentials, disk"))
	}
	for i, c := range m.checks {
		mark := map[doctor.Level]string{doctor.OK: sDim.Render("✓"), doctor.Warn: sAmber.Render("!"), doctor.Fail: sAmber.Render("✗")}[c.Level]
		line := fmt.Sprintf("%-30s %s", c.Title, truncate(c.Detail, 40))
		fix := ""
		if c.Fix != "" {
			fix = "  " + c.Fix
		}
		if i == d.cursor {
			body = append(body, mark+"  "+sel(w-10, truncate(line+fix, w-10)))
		} else {
			body = append(body, mark+"  "+sText.Render(line)+sSoft.Render(truncate(fix, w-12-len(line))))
		}
	}
	b.WriteString(box(w, strings.Join(body, "\n")) + "\n")
	if d.msg != "" {
		b.WriteString("  " + sAmber.Render(truncate(d.msg, w-4)) + "\n")
	}
	if n := m.releaseNote(); n != "" {
		b.WriteString("  " + sAmber.Render(truncate(n, w-4)) + "\n")
	}
	keys := []string{"↑↓", "move", "c", "copy the fix command", "r", "re-check", "esc", "back"}
	if m.newer != "" {
		keys = append(keys, "u", "update")
	}
	if d.cursor < len(m.checks) && m.checks[d.cursor].Level != doctor.OK {
		switch id := m.checks[d.cursor].ID; {
		case strings.HasPrefix(id, "approval-"):
			keys = append([]string{"a", "approve in sbx"}, keys...)
		case id == "policy":
			keys = append([]string{"a", "set the policy"}, keys...)
		case strings.HasPrefix(id, "agent-"):
			keys = append([]string{"a", "connect"}, keys...)
		}
	}
	if d.policy {
		b.WriteString(box(w, sBold.Render("Global network policy")+"\n  "+sText.Render("$ "+doctor.PolicyInitCommand)+"\n  "+sAmber.Render("changes the global sbx policy: every sbx sandbox on this Mac, not only burner's")) + "\n")
		keys = []string{"enter", "run the command", "esc", "cancel"}
	}
	b.WriteString(hints(keys...))
	return b.String()
}

// newModel is the "New recipe" form: category, then name; it scaffolds
// into the user's recipes like `burner new`.
type newModel struct {
	step   int
	cat    int
	name   string
	err    string
	done   string
	cursor int
}

func newNewModel() *newModel { return &newModel{} }

// tildify shows a path under the home folder as ~/…
func tildify(p string) string {
	if home, err := os.UserHomeDir(); err == nil && home != "" && strings.HasPrefix(p, home+"/") {
		return "~" + p[len(home):]
	}
	return p
}

func (m model) updateNew(msg tea.Msg) (tea.Model, tea.Cmd) {
	n := m.newr
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	if n.done != "" {
		m.scr = scrHome
		return m, nil
	}
	switch n.step {
	case 0:
		switch k.String() {
		case "up", "k":
			if n.cat > 0 {
				n.cat--
			}
		case "down", "j":
			if n.cat < len(scaffold.Categories)-1 {
				n.cat++
			}
		case "enter":
			n.step = 1
		case "esc":
			m.scr = scrHome
		}
	case 1:
		switch k.Type {
		case tea.KeyEsc:
			n.step, n.err = 0, ""
		case tea.KeyEnter:
			dest, err := scaffold.New(m.cfg.Root+"/template", catalog.UserRecipesDir(), scaffold.Categories[n.cat], strings.TrimSpace(n.name))
			if err != nil {
				n.err = err.Error()
				return m, nil
			}
			n.done = dest
		case tea.KeyBackspace:
			if r := []rune(n.name); len(r) > 0 {
				n.name = string(r[:len(r)-1])
			}
		case tea.KeyRunes:
			if len(n.name) < 60 {
				n.name += string(k.Runes)
			}
		}
	}
	return m, nil
}

func (m model) viewNew() string {
	n := m.newr
	w := m.w
	var b strings.Builder
	b.WriteString(sBold.Render("New recipe") + "  " + sDim.Render("scaffolded into "+tildify(catalog.UserRecipesDir())) + "\n\n")
	if n.done != "" {
		b.WriteString(box(w, sText.Render("Created "+n.done)+"\n"+sDim.Render("Next: edit RECIPE.md, recipe.yaml and AGENTS.md, then run: burner lint "+n.done)) + "\n")
		b.WriteString(hints("any key", "back"))
		return b.String()
	}
	var body []string
	body = append(body, sBold.Render("Category"), "")
	for i, c := range scaffold.Categories {
		if i == n.cat {
			body = append(body, sel(w-6, "❯ "+c))
		} else if n.step == 0 {
			body = append(body, "  "+sSoft.Render(c))
		}
	}
	if n.step == 1 {
		body = append(body, "", sBold.Render("Name"), "", "❯ "+sText.Render(n.name)+sDim.Render("▌"))
		if n.err != "" {
			body = append(body, sAmber.Render(n.err))
		}
	}
	b.WriteString(box(w, strings.Join(body, "\n")) + "\n")
	b.WriteString(hints("↑↓", "move", "enter", "next", "esc", "back"))
	return b.String()
}
