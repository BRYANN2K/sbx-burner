package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/BRYANN2K/sbx-burner/internal/catalog"
	"github.com/BRYANN2K/sbx-burner/internal/doctor"
	"github.com/BRYANN2K/sbx-burner/internal/sanitize"
	"github.com/BRYANN2K/sbx-burner/internal/series"
)

// lastRun is the newest readable report under the runs folder.
type lastRun struct {
	recipe, agent string
	findings      int
	when          time.Time
}

type lastRunMsg *lastRun

// maxRunDirs bounds the scan of the runs folder.
const maxRunDirs = 500

// findLastRun returns the newest valid report.json in runsDir; malformed or
// oversized reports are skipped.
func findLastRun(runsDir string) *lastRun {
	entries, err := os.ReadDir(runsDir)
	if err != nil {
		return nil
	}
	type cand struct {
		path string
		mod  time.Time
	}
	var cands []cand
	for _, e := range entries {
		if len(cands) >= maxRunDirs {
			break
		}
		if !e.IsDir() {
			continue
		}
		p := filepath.Join(runsDir, e.Name(), "report.json")
		if st, err := os.Lstat(p); err == nil && st.Mode().IsRegular() {
			cands = append(cands, cand{p, st.ModTime()})
		}
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].mod.After(cands[j].mod) })
	for _, c := range cands {
		raw, err := readCapped(c.path)
		if err != nil {
			continue
		}
		var r struct {
			Run struct {
				Recipe string `json:"recipe"`
				Agent  string `json:"agent"`
			} `json:"run"`
			Counts struct {
				Findings *int `json:"findings"`
			} `json:"counts"`
		}
		if json.Unmarshal(raw, &r) != nil || r.Run.Recipe == "" || r.Counts.Findings == nil {
			continue
		}
		return &lastRun{
			recipe:   sanitize.Line(recipeName(r.Run.Recipe), 80),
			agent:    sanitize.Line(r.Run.Agent, 40),
			findings: *r.Counts.Findings,
			when:     c.mod,
		}
	}
	return nil
}

func (l *lastRun) String(now time.Time) string {
	f := fmt.Sprintf("%d findings", l.findings)
	if l.findings == 1 {
		f = "1 finding"
	}
	when := l.when.Format("2006-01-02 15:04")
	if y1, m1, d1 := l.when.Date(); func() bool { y2, m2, d2 := now.Date(); return y1 == y2 && m1 == m2 && d1 == d2 }() {
		when = "today " + l.when.Format("15:04")
	}
	parts := []string{l.recipe}
	if l.agent != "" {
		parts = append(parts, l.agent)
	}
	return strings.Join(append(parts, f, when), sDim.Render("  ·  "))
}

// agentsLine: "ready" when the credential check passed, else "sign in".
func (m model) agentsLine() string {
	if m.checking {
		return sAmber.Render(m.spin()) + " " + sDim.Render("checking credentials")
	}
	var parts []string
	for _, a := range []string{"codex", "claude", "devin"} {
		found := false
		for _, c := range m.checks {
			if c.ID == "agent-"+a {
				found = true
			}
		}
		if !found {
			continue
		}
		state := sDim.Render("sign in")
		if doctor.AgentReady(m.checks, a) {
			state = sSoft.Render("ready")
		}
		parts = append(parts, a+" "+state)
	}
	line := strings.Join(parts, sDim.Render("  ·  "))
	if need := doctor.ApprovalsNeeded(m.checks); len(need) > 0 {
		line += sDim.Render("  ·  ") + sAmber.Render("approvals needed: "+strings.Join(need, ", "))
	}
	return line
}

// headLines renders the top box: logo left, info right, vertically
// centred. Narrow or short terminals get one line.
func (m model) headLines() []string {
	name := sBold.Render("burner") + "  " + sDim.Render(m.cfg.Version)
	folder := sDim.Render(tildify(m.cfg.Cwd))
	if m.w < 80 || m.h < 30 {
		return []string{header(m.w, name+"  "+folder, "")}
	}
	const padX, gap = 3, 3
	infoW := m.w - 2 - 2*padX - logoW - gap
	kv := func(k, v string) string { return ellipsis(sDim.Render(fmt.Sprintf("%-10s", k))+sText.Render(v), infoW) }
	info := []string{name, ellipsis(folder, infoW), "", kv("agents", m.agentsLine())}
	if m.last != nil {
		info = append(info, kv("last run", m.last.String(m.cfg.Now())))
	}
	if saved := series.List(catalog.Home()); len(saved) > 0 {
		var names []string
		for i := len(saved) - 1; i >= 0 && len(names) < 3; i-- {
			names = append(names, saved[i].Name)
		}
		info = append(info, kv("series", strings.Join(names, " · ")))
	}
	logo := m.logoLines()
	top := (len(logo) - len(info)) / 2
	var rows []string
	for i, l := range logo {
		row := sAmber.Render(l)
		if j := i - top; j >= 0 && j < len(info) {
			row += strings.Repeat(" ", gap) + info[j]
		}
		rows = append(rows, row)
	}
	st := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colLine).Padding(1, padX).Width(m.w - 2)
	return strings.Split(st.Render(strings.Join(rows, "\n")), "\n")
}
