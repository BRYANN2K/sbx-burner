package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/BRYANN2K/sbx-burner/internal/sanitize"
)

// reportModel reads report.json (and policy-log.json) from the run folder.
// Everything in it can come from the agent, so every string is cleaned.
type reportModel struct {
	mdPath  string
	dir     string
	runsDir string
	exit    int
	took    time.Duration
	rep     reportJSON
	err     string
	allowed []string
	blocked []string
	sc      scroller
	msg     string
}

type reportJSON struct {
	Summary string `json:"summary"`
	Counts  struct {
		Findings   int `json:"findings"`
		Hypotheses int `json:"hypotheses"`
	} `json:"counts"`
	Findings []struct {
		ID       string `json:"id"`
		Title    string `json:"title"`
		Severity string `json:"severity"`
		Location string `json:"location"`
		Tool     string `json:"tool"`
		Rule     string `json:"rule"`
	} `json:"findings"`
	Hypotheses []struct {
		ID    string `json:"id"`
		Title string `json:"title"`
	} `json:"hypotheses"`
	Artifacts []struct {
		Path string `json:"path"`
	} `json:"artifacts"`
	Gate struct {
		Demoted    []json.RawMessage `json:"demoted"`
		Redactions int               `json:"redactions"`
	} `json:"gate"`
}

const maxReport = 8 << 20

func newReport(mdPath, dir, runsDir string, exit int, took time.Duration) *reportModel {
	r := &reportModel{mdPath: mdPath, dir: dir, runsDir: runsDir, exit: exit, took: took}
	jp := strings.TrimSuffix(mdPath, ".md") + ".json"
	if raw, err := readCapped(jp); err != nil {
		r.err = "no report.json in " + dir
	} else if err := json.Unmarshal(raw, &r.rep); err != nil {
		r.err = "report.json is not valid JSON"
	}
	if raw, err := readCapped(filepath.Join(dir, "policy-log.json")); err == nil {
		var pl struct {
			Allowed []struct {
				Host string `json:"host"`
			} `json:"allowed"`
			Blocked []struct {
				Host string `json:"host"`
			} `json:"blocked"`
		}
		if json.Unmarshal(raw, &pl) == nil {
			for _, a := range pl.Allowed {
				r.allowed = appendUniq(r.allowed, sanitize.Line(a.Host, 300))
			}
			for _, b := range pl.Blocked {
				r.blocked = appendUniq(r.blocked, sanitize.Line(b.Host, 300))
			}
		}
	}
	return r
}

func appendUniq(list []string, v string) []string {
	if v == "" {
		return list
	}
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// readCapped reads a regular file (no symlink) of bounded size.
func readCapped(p string) ([]byte, error) {
	st, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > maxReport {
		return nil, fmt.Errorf("%s: not a regular file under 8 MB", p)
	}
	return os.ReadFile(p)
}

func (m model) updateReport(msg tea.Msg) (tea.Model, tea.Cmd) {
	r := m.report
	if mm, ok := msg.(tea.MouseMsg); ok {
		r.sc.mouse(mm)
		return m, nil
	}
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	r.msg = ""
	if r.sc.key(k.String(), true) {
		return m, nil
	}
	switch k.String() {
	case "o":
		r.msg = openPath(r.mdPath, r.runsDir, false)
	case "f":
		r.msg = openPath(r.dir, r.runsDir, true)
	case "r":
		if m.plan != nil {
			m.plan = newPlan(m.plan.opts)
			m.scr = scrPlan
			return m, m.plan.start(m)
		}
	case "enter", "esc":
		m.home.msg = ""
		m.scr = scrHome
	case "q":
		return m, tea.Quit
	}
	return m, nil
}

// inside reports whether p is under root.
func inside(p, root string) bool {
	ap, err1 := filepath.Abs(p)
	ar, err2 := filepath.Abs(root)
	if err1 != nil || err2 != nil {
		return false
	}
	rel, err := filepath.Rel(ar, ap)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

// openPath opens report.md as text, or reveals the run folder in the file
// manager. Only paths under the runs folder are opened.
func openPath(p, runsDir string, reveal bool) string {
	if p == "" {
		return "nothing to open"
	}
	if !inside(p, runsDir) {
		return "not opened: " + p + " is outside " + runsDir
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		if reveal {
			cmd = exec.Command("open", "-R", "--", p)
		} else {
			cmd = exec.Command("open", "-t", "--", p)
		}
	default:
		cmd = exec.Command("xdg-open", p)
	}
	if err := cmd.Start(); err != nil {
		return "could not open " + p
	}
	go func() { _ = cmd.Wait() }()
	return "opened " + p
}

func (m model) viewReport() string {
	r := m.report
	w := m.w
	var b strings.Builder
	head := sBold.Render("■ done") + sDim.Render(fmt.Sprintf(" · exit %d · %s", r.exit, clock(r.took)))
	b.WriteString(head + "\n\n")
	if r.err != "" {
		b.WriteString(box(w, sAmber.Render(r.err)) + "\n")
		b.WriteString(hints("f", "reveal run folder", "enter", "back to recipes", "q", "quit"))
		return b.String()
	}
	inner := w - 6
	rep := r.rep
	var body []string
	body = append(body, sBold.Render("Findings")+"  "+sDim.Render(fmt.Sprintf("%d proven · %d demoted", len(rep.Findings), len(rep.Gate.Demoted))), "")
	if len(rep.Findings) == 0 {
		body = append(body, sDim.Render("  none"))
	}
	for _, f := range rep.Findings {
		sevRaw := sanitize.Line(f.Severity, 20)
		sev := fmt.Sprintf("%-9s", sevRaw)
		rest := fmt.Sprintf("  %-26s %s", truncate(sanitize.Line(f.ID, 40), 26), sanitize.Line(f.Title, 300))
		if sevRaw == "critical" {
			body = append(body, sRed.Render(sev)+sText.Render(rest))
		} else {
			body = append(body, sSoft.Render(sev)+sText.Render(rest))
		}
		meta := []string{}
		for _, v := range []string{f.Location, f.Tool, f.Rule} {
			if v = sanitize.Line(v, 200); v != "" {
				meta = append(meta, v)
			}
		}
		if len(meta) > 0 {
			body = append(body, "  "+sDim.Render(strings.Join(meta, " · ")))
		}
	}
	body = append(body, "", sBold.Render("Hypotheses")+"  "+sDim.Render("unproven, not findings"), "")
	if len(rep.Hypotheses) == 0 {
		body = append(body, sDim.Render("  none"))
	}
	for _, h := range rep.Hypotheses {
		body = append(body, "  "+sSoft.Render(truncate(fmt.Sprintf("%-26s %s", sanitize.Line(h.ID, 40), sanitize.Line(h.Title, 300)), inner-4)))
	}
	if len(r.allowed)+len(r.blocked) > 0 {
		body = append(body, "", sBold.Render("Network"))
		if len(r.allowed) > 0 {
			body = append(body, "  "+sDim.Render("allowed  ")+sSoft.Render(truncate(strings.Join(r.allowed, " · "), inner-13)))
		}
		if len(r.blocked) > 0 {
			body = append(body, "  "+sDim.Render("blocked  ")+sSoft.Render(truncate(strings.Join(r.blocked, " · "), inner-13)))
		}
	}
	// Fixed: head (2), box border (2), footer lines below the box.
	below := 3
	if r.msg != "" {
		below++
	}
	scH := max(3, m.h-4-below)
	b.WriteString(box(w, strings.Join(r.sc.view(body, inner, scH), "\n")) + "\n")
	var arts []string
	for _, a := range rep.Artifacts {
		arts = append(arts, filepath.Base(sanitize.Line(a.Path, 200)))
	}
	foot := "report.md · report.json"
	if len(arts) > 0 {
		foot += " · evidence/artifacts (" + strings.Join(arts, ", ") + ")"
	}
	foot += fmt.Sprintf(" · redactions %d", rep.Gate.Redactions)
	b.WriteString("  " + sDim.Render(truncate(foot, w-4)) + "\n")
	b.WriteString("  " + sDim.Render(truncate(r.dir, w-4)) + "\n")
	if r.msg != "" {
		b.WriteString("  " + sAmber.Render(truncate(r.msg, w-4)) + "\n")
	}
	b.WriteString(hints("↑↓", "scroll", "o", "open report.md", "f", "reveal run folder", "r", "run again", "enter", "recipes", "shift+drag", "select text", "q", "quit"))
	return b.String()
}
