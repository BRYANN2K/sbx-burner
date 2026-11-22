package tui

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/BRYANN2K/sbx-burner/internal/sanitize"
)

// stepLogPath is the runner's log of one step: <run dir>/logs/<step>.log.
func stepLogPath(runDir, step string) string {
	return filepath.Join(runDir, "logs", strings.ReplaceAll(step, ":", "_")+".log")
}

const logTail = 256 << 10

// readTail returns the last logTail bytes of a regular file.
func readTail(p string) (string, error) {
	st, err := os.Lstat(p)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", os.ErrInvalid
	}
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if st.Size() > logTail {
		if _, err := f.Seek(st.Size()-logTail, io.SeekStart); err != nil {
			return "", err
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, logTail))
	return string(b), err
}

var (
	logMarker  = regexp.MustCompile(`^(\$ |\[exit \d+\]$|--- [a-z ]+ ---$)`)
	errorWords = regexp.MustCompile(`(?i)(error|refused|failed|denied|not found|no such|cannot|invalid|too long|not supported)`)
)

// lastError picks the line that best says why a step failed: the last line
// with an error word, else the last line with text. One sanitized line.
func lastError(log string) string {
	lines := strings.Split(log, "\n")
	fallback := ""
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if l == "" || logMarker.MatchString(l) {
			continue
		}
		if fallback == "" {
			fallback = l
		}
		if errorWords.MatchString(l) {
			return sanitize.Line(l, 300)
		}
	}
	return sanitize.Line(fallback, 300)
}

// logModel shows a step's full log in the viewport.
type logModel struct {
	step  string
	path  string
	lines []string
	err   string
	sc    scroller
}

func newLogView(step, path string) *logModel {
	lv := &logModel{step: step, path: path}
	text, err := readTail(path)
	if err != nil {
		lv.err = "no log at " + path
		return lv
	}
	for _, l := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		lv.lines = append(lv.lines, sanitize.Line(l, 2000))
	}
	lv.sc.follow = true
	return lv
}

func (m model) updateLog(msg tea.Msg) (tea.Model, tea.Cmd) {
	lv := m.logv
	switch msg := msg.(type) {
	case tea.MouseMsg:
		lv.sc.mouse(msg)
	case tea.KeyMsg:
		if lv.sc.key(msg.String(), true) {
			return m, nil
		}
		switch msg.String() {
		case "esc", "enter":
			m.scr = scrLive
		case "q":
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m model) viewLog() string {
	lv := m.logv
	w := m.w
	var b strings.Builder
	b.WriteString(header(w, crumb("log", lv.step), sDim.Render(tildify(lv.path))) + "\n\n")
	var body []string
	if lv.err != "" {
		body = []string{sAmber.Render(lv.err)}
	} else {
		var styled []string
		for _, l := range lv.lines {
			styled = append(styled, sSoft.Render(l))
		}
		body = lv.sc.view(styled, w-4, max(3, m.h-6))
	}
	b.WriteString(box(w, strings.Join(body, "\n")) + "\n")
	b.WriteString(hints("↑↓ pgup pgdn", "scroll", "w", wrapLabel(lv.sc.wrap), "esc", "back to the run", "q", "quit"))
	return b.String()
}
