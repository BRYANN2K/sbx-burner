package tui

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/creack/pty"
	"github.com/hinshun/vt10x"
)

// Every command burner runs for the user (sbx prompts, sign-ins, the
// approval, an agent's own TUI) runs inside burner, in an embedded terminal
// panel: burner never leaves the screen, and whatever the command asks is
// answered here, in its own interface. ctrl+q (or ctrl+]) stops it.

type embTerm struct {
	title   string
	cmd     *exec.Cmd
	ptmx    *os.File
	vt      vt10x.Terminal
	cols    int
	rows    int
	done    func(error) tea.Msg
	update  chan struct{}
	exited  chan error
	once    sync.Once
	ended   bool
	exitErr error
	watch   func() bool // closes the panel when it reports true (e.g. the sign-in is stored)
	lastEsc time.Time
	autoOK  bool // close by itself when the command succeeds
	closing bool // the user asked to leave: close as soon as it exits
}

// openTermMsg asks the model to open an embedded terminal for argv.
type openTermMsg struct {
	title  string
	argv   []string
	done   func(error) tea.Msg
	watch  func() bool
	autoOK bool
}

type termOutMsg struct{ t *embTerm }

type termWatchMsg struct {
	t  *embTerm
	ok bool
}

func (t *embTerm) poll() tea.Cmd {
	if t.watch == nil {
		return nil
	}
	return tea.Tick(2*time.Second, func(time.Time) tea.Msg { return termWatchMsg{t, t.watch()} })
}

// termAutoCmd is termCmd for a command whose success needs no reading:
// the panel closes by itself when it exits 0, and stays open on a failure.
func termAutoCmd(title string, argv []string, done func(error) tea.Msg) tea.Cmd {
	if len(argv) == 0 {
		return nil
	}
	return func() tea.Msg { return openTermMsg{title: title, argv: argv, done: done, autoOK: true} }
}

// termWatchCmd is termCmd with a watcher: the panel closes by itself as soon
// as watch reports true, for example once sbx has stored a sign-in.
func termWatchCmd(title string, argv []string, watch func() bool, done func(error) tea.Msg) tea.Cmd {
	if len(argv) == 0 {
		return nil
	}
	return func() tea.Msg { return openTermMsg{title: title, argv: argv, done: done, watch: watch} }
}

type termExitMsg struct {
	t   *embTerm
	err error
}

// termCmd replaces tea.ExecProcess: the command runs in burner's own panel.
func termCmd(title string, argv []string, done func(error) tea.Msg) tea.Cmd {
	if len(argv) == 0 {
		return nil
	}
	return func() tea.Msg { return openTermMsg{title: title, argv: argv, done: done} }
}

func termSize(w, h int) (int, int) {
	cols, rows := w-8, h-8
	if cols < 40 {
		cols = 40
	}
	if rows < 10 {
		rows = 10
	}
	return cols, rows
}

func startTerm(o openTermMsg, w, h int) (*embTerm, tea.Cmd, error) {
	cols, rows := termSize(w, h)
	c := exec.Command(o.argv[0], o.argv[1:]...)
	c.Env = append(os.Environ(), "TERM=xterm-256color")
	ptmx, err := pty.StartWithSize(c, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
	if err != nil {
		return nil, nil, err
	}
	t := &embTerm{
		title: o.title, cmd: c, ptmx: ptmx, vt: vt10x.New(vt10x.WithSize(cols, rows)),
		cols: cols, rows: rows, done: o.done, watch: o.watch, autoOK: o.autoOK,
		update: make(chan struct{}, 1), exited: make(chan error, 1),
	}
	go t.pump()
	return t, tea.Batch(t.wait(), t.poll()), nil
}

// pump copies the command's output into the emulator.
func (t *embTerm) pump() {
	buf := make([]byte, 32*1024)
	for {
		n, err := t.ptmx.Read(buf)
		if n > 0 {
			_, _ = t.vt.Write(buf[:n])
			select {
			case t.update <- struct{}{}:
			default:
			}
		}
		if err != nil {
			break
		}
	}
	err := t.cmd.Wait()
	t.exited <- err
}

func (t *embTerm) wait() tea.Cmd {
	return func() tea.Msg {
		select {
		case <-t.update:
			return termOutMsg{t}
		case err := <-t.exited:
			return termExitMsg{t, err}
		}
	}
}

func (t *embTerm) resize(w, h int) {
	cols, rows := termSize(w, h)
	if cols == t.cols && rows == t.rows {
		return
	}
	t.cols, t.rows = cols, rows
	t.vt.Resize(cols, rows)
	_ = pty.Setsize(t.ptmx, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
}

func (t *embTerm) stop() {
	t.once.Do(func() {
		if t.cmd.Process != nil {
			_ = t.cmd.Process.Kill()
		}
		_ = t.ptmx.Close()
	})
}

var keyBytes = map[string]string{
	"enter": "\r", "tab": "\t", "backspace": "\x7f", "esc": "\x1b", " ": " ",
	"up": "\x1b[A", "down": "\x1b[B", "right": "\x1b[C", "left": "\x1b[D",
	"home": "\x1b[H", "end": "\x1b[F", "pgup": "\x1b[5~", "pgdown": "\x1b[6~", "delete": "\x1b[3~",
	"ctrl+c": "\x03", "ctrl+d": "\x04", "ctrl+u": "\x15", "ctrl+w": "\x17", "ctrl+l": "\x0c",
	"shift+tab": "\x1b[Z",
}

func (t *embTerm) key(k tea.KeyMsg) {
	if k.Type == tea.KeyRunes {
		_, _ = t.ptmx.Write([]byte(string(k.Runes)))
		return
	}
	if b, ok := keyBytes[k.String()]; ok {
		_, _ = t.ptmx.Write([]byte(b))
	}
}

// view renders the emulator screen inside a framed panel.
func (t *embTerm) view(w, h int) string {
	t.vt.Lock()
	cur := t.vt.Cursor()
	lines := make([]string, t.rows)
	for y := 0; y < t.rows; y++ {
		var sb strings.Builder
		for x := 0; x < t.cols; x++ {
			ch := t.vt.Cell(x, y).Char
			if ch == 0 {
				ch = ' '
			}
			if x == cur.X && y == cur.Y && t.vt.CursorVisible() {
				sb.WriteString(sSel.Render(string(ch)))
				continue
			}
			sb.WriteRune(ch)
		}
		lines[y] = strings.TrimRight(sb.String(), " ")
	}
	t.vt.Unlock()
	right := sDim.Render("ctrl+\\ or esc esc to leave")
	if t.ended {
		right = sSoft.Render("done") + sDim.Render(" · enter close")
		if t.exitErr != nil {
			right = sAmber.Render("exited: "+t.exitErr.Error()) + sDim.Render(" · enter close")
		}
	}
	head := header(t.cols, sBold.Render(t.title), right)
	body := head + "\n\n" + strings.Join(lines, "\n")
	panel := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colLine).Padding(0, 1).Render(body)
	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, panel)
}

// updateTerm handles messages while an embedded terminal is open. It reports
// whether the message was consumed.
func (m model) updateTerm(msg tea.Msg) (model, tea.Cmd, bool) {
	switch msg := msg.(type) {
	case openTermMsg:
		t, cmd, err := startTerm(msg, m.w, m.h)
		if err != nil {
			if msg.done != nil {
				return m, func() tea.Msg { return msg.done(err) }, true
			}
			return m, nil, true
		}
		m.term = t
		return m, cmd, true
	}
	t := m.term
	if t == nil {
		return m, nil, false
	}
	switch msg := msg.(type) {
	case termOutMsg:
		if msg.t != t {
			return m, nil, true
		}
		return m, t.wait(), true
	case termExitMsg:
		if msg.t != t {
			return m, nil, true
		}
		t.stop()
		if t.closing || (msg.err == nil && t.autoOK) {
			m.term = nil
			if t.done != nil {
				d := t.done
				return m, func() tea.Msg { return d(nil) }, true
			}
			return m, nil, true
		}
		// Keep the panel open so the command's last words stay readable.
		t.ended, t.exitErr = true, msg.err
		return m, nil, true
	case termWatchMsg:
		if msg.t != t || t.ended {
			return m, nil, true
		}
		if msg.ok {
			t.stop()
			m.term = nil
			if t.done != nil {
				d := t.done
				return m, func() tea.Msg { return d(nil) }, true
			}
			return m, nil, true
		}
		return m, t.poll(), true
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		t.resize(m.w, m.h)
		return m, nil, true
	case tea.KeyMsg:
		if t.ended {
			if k := msg.String(); k == "enter" || k == "esc" || k == "q" {
				m.term = nil
				if t.done != nil {
					d, err := t.done, t.exitErr
					return m, func() tea.Msg { return d(err) }, true
				}
			}
			return m, nil, true
		}
		k := msg.String()
		// Leave keys. Terminals and agents eat some of them (Orca takes
		// ctrl+q, Codex uses esc esc), so several work; a quick esc esc
		// often arrives as alt+esc.
		leave := k == "ctrl+\\" || k == "ctrl+q" || k == "ctrl+]" || k == "alt+esc" || k == "f10"
		if k == "esc" {
			if time.Since(t.lastEsc) < 600*time.Millisecond {
				leave = true
			}
			t.lastEsc = time.Now()
		}
		if leave {
			t.closing = true
			t.stop()
			return m, nil, true
		}
		t.key(msg)
		return m, nil, true
	case tea.MouseMsg:
		return m, nil, true
	}
	return m, nil, false
}

var errTermStopped = errors.New("stopped")
