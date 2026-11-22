package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// scroller is the viewport used by the plan, the live log and the report:
// the box scrolls, the page around it does not. Long lines are cut with
// "…" unless wrap is on (w).
type scroller struct {
	offset int  // first visible line
	follow bool // stick to the last line (live log)
	wrap   bool
	total  int // lines at the last render
	height int // visible lines at the last render
}

func (s *scroller) inner() int {
	if s.total <= s.height {
		return s.height
	}
	return max(1, s.height-2) // two lines for the indicators
}

func (s *scroller) maxOffset() int { return max(0, s.total-s.inner()) }

func (s *scroller) scroll(n int) {
	s.offset += n
	if s.offset < 0 {
		s.offset = 0
	}
	if s.offset >= s.maxOffset() {
		s.offset = s.maxOffset()
		s.follow = true
	} else if n < 0 {
		s.follow = false
	}
}

// key handles a scroll key; arrows only when arrows is true (the live view
// uses them for answers while a question is open).
func (s *scroller) key(k string, arrows bool) bool {
	page := max(1, s.inner()-1)
	switch k {
	case "up", "k":
		if !arrows {
			return false
		}
		s.scroll(-1)
	case "down", "j":
		if !arrows {
			return false
		}
		s.scroll(1)
	case "pgup", "ctrl+u":
		s.scroll(-page)
	case "pgdown", "ctrl+d", " ":
		if k == " " && !arrows {
			return false
		}
		s.scroll(page)
	case "home", "g":
		s.offset, s.follow = 0, false
	case "end", "G":
		s.offset, s.follow = s.maxOffset(), true
	case "w":
		s.wrap = !s.wrap
	default:
		return false
	}
	return true
}

func (s *scroller) mouse(msg tea.MouseMsg) bool {
	if msg.Action != tea.MouseActionPress {
		return false
	}
	switch msg.Button {
	case tea.MouseButtonWheelUp:
		s.scroll(-3)
	case tea.MouseButtonWheelDown:
		s.scroll(3)
	default:
		return false
	}
	return true
}

// view returns exactly h lines of width w. Without wrap only the visible
// lines are measured, so a long log costs little per frame.
func (s *scroller) view(lines []string, w, h int) []string {
	out := lines
	if s.wrap {
		out = nil
		for _, l := range lines {
			if lipgloss.Width(l) > w {
				out = append(out, strings.Split(lipgloss.NewStyle().Width(w).Render(l), "\n")...)
			} else {
				out = append(out, l)
			}
		}
	}
	s.total, s.height = len(out), max(1, h)
	if s.follow || s.offset > s.maxOffset() {
		s.offset = s.maxOffset()
	}
	cut := func(ls []string) []string {
		r := make([]string, len(ls))
		for i, l := range ls {
			r[i] = ellipsis(l, w)
		}
		return r
	}
	if s.total <= s.height {
		view := cut(out)
		for len(view) < s.height {
			view = append(view, "")
		}
		return view
	}
	in := s.inner()
	view := []string{""}
	if s.offset > 0 {
		view[0] = sDim.Render(fmt.Sprintf("↑ %d more lines", s.offset))
	}
	view = append(view, cut(out[s.offset:s.offset+in])...)
	if rest := s.total - s.offset - in; rest > 0 {
		view = append(view, sDim.Render(fmt.Sprintf("↓ %d more lines", rest)))
	} else {
		view = append(view, "")
	}
	return view
}

// ellipsis cuts a styled line to w cells, ending with "…" when cut.
func ellipsis(l string, w int) string {
	if lipgloss.Width(l) <= w {
		return l
	}
	return lipgloss.NewStyle().MaxWidth(w-1).Render(l) + sDim.Render("…")
}
