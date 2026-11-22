package tui

import (
	"strings"

	"github.com/BRYANN2K/sbx-burner/internal/doctor"
)

// machineIDs are setup's machine checklist, in install order: each line
// needs the ones above it.
var machineIDs = []string{"brew", "sbx", "runtime", "buildx", "git", "python", "sbx-login", "policy", "git-login", "disk"}

var machineNames = map[string]string{
	"brew": "Homebrew", "sbx": "sbx", "runtime": "Container runtime", "buildx": "Docker buildx",
	"git": "git", "python": "python3", "sbx-login": "sbx sign-in", "policy": "Global network policy",
	"git-login": "GitHub login", "disk": "Free disk",
}

func (m model) machineRows() []doctor.Result {
	var out []doctor.Result
	for _, id := range machineIDs {
		if c, ok := m.check(id); ok {
			out = append(out, c)
		}
	}
	return out
}

// nextRed is the first line that still needs action, from i on, then from
// the top; i itself when every line is green.
func nextRed(rows []doctor.Result, i int) int {
	for k := 0; k < len(rows); k++ {
		j := (i + k) % len(rows)
		if rows[j].Level != doctor.OK {
			return j
		}
	}
	if i >= len(rows) {
		return 0
	}
	return i
}

// pickAction is the chosen action of a line (chip clamps to the list).
func pickAction(c doctor.Result, chip int) (doctor.Action, bool) {
	if c.Level == doctor.OK || len(c.Actions) == 0 {
		return doctor.Action{}, false
	}
	if chip < 0 || chip >= len(c.Actions) {
		chip = 0
	}
	return c.Actions[chip], true
}

// actionLine is the command as the user would type it: the $brew prefix
// of a shell line reads as plain brew.
func actionLine(a doctor.Action) string {
	if len(a.Argv) == 0 {
		return a.URL
	}
	if len(a.Argv) == 3 && a.Argv[0] == "/bin/sh" && a.Argv[1] == "-c" {
		line := a.Argv[2]
		if strings.HasPrefix(line, "brew=") {
			if i := strings.Index(line, "; "); i > 0 {
				line = line[i+2:]
			}
		}
		line = strings.ReplaceAll(line, `"$("$brew" --prefix)`, `"$(brew --prefix)`)
		return strings.ReplaceAll(line, `"$brew"`, "brew")
	}
	if len(a.Argv) == 3 && a.Argv[0] == "/bin/bash" && a.Argv[1] == "-c" {
		return a.Argv[2]
	}
	if strings.HasSuffix(a.Argv[0], "/brew") {
		return strings.Join(append([]string{"brew"}, a.Argv[1:]...), " ")
	}
	return strings.Join(a.Argv, " ")
}

func machineTitle(id string) string {
	if n, ok := machineNames[id]; ok {
		return n
	}
	return id
}
