package tui

import (
	"os"
	"regexp"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// Palette from the validated mock (Grok Build style): greys on #141414,
// one amber accent, red only for critical findings.
var (
	colBG    = lipgloss.Color("#141414")
	colSel   = lipgloss.Color("#242424")
	colLine  = lipgloss.Color("#333333")
	colText  = lipgloss.Color("#e1e1e1")
	colSoft  = lipgloss.Color("#c8c8c8")
	colDim   = lipgloss.Color("#6c6c6c")
	colFaint = lipgloss.Color("#505058")
	colAmber = lipgloss.Color("#e0af68")
	colBlue  = lipgloss.Color("#7aa2f7")
	colRed   = lipgloss.Color("#e06c75")
)

var (
	sText  = lipgloss.NewStyle().Foreground(colText)
	sSoft  = lipgloss.NewStyle().Foreground(colSoft)
	sDim   = lipgloss.NewStyle().Foreground(colDim)
	sFaint = lipgloss.NewStyle().Foreground(colFaint)
	sAmber = lipgloss.NewStyle().Foreground(colAmber)
	sBlue  = lipgloss.NewStyle().Foreground(colBlue)
	sRed   = lipgloss.NewStyle().Foreground(colRed)
	sBold  = lipgloss.NewStyle().Foreground(colText).Bold(true)
	sSel   = lipgloss.NewStyle().Background(colSel).Foreground(colText)

	sBox = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colLine).Padding(0, 1)
)

// colorOn is false with NO_COLOR or a dumb terminal; the view then has no
// colour and no background fill.
var colorOn = true

// setupColor applies NO_COLOR. Called once before the program starts.
func setupColor() {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		lipgloss.SetColorProfile(termenv.Ascii)
		colorOn = false
	}
}

func box(width int, body string) string {
	if width < 10 {
		width = 10
	}
	return sBox.Width(width - 2).Render(body)
}

// sel renders the highlighted row of a list across the given width.
func sel(width int, s string) string {
	pad := width - lipgloss.Width(s)
	if pad > 0 {
		s += strings.Repeat(" ", pad)
	}
	return sSel.Render(s)
}

var resetRE = regexp.MustCompile(`\x1b\[0?m`)

// paintBG fills every cell with the mock background: each line is padded
// to the width and the background is restored after every SGR reset.
func paintBG(view string, width int) string {
	if !colorOn {
		return view
	}
	const bg = "\x1b[48;2;20;20;20m"
	lines := strings.Split(view, "\n")
	for i, l := range lines {
		pad := width - lipgloss.Width(l)
		if pad < 0 {
			pad = 0
		}
		l = resetRE.ReplaceAllStringFunc(l, func(m string) string { return m + bg })
		lines[i] = bg + l + strings.Repeat(" ", pad) + "\x1b[0m"
	}
	return strings.Join(lines, "\n")
}

// hints renders the bottom key bar: pairs of key, action.
func hints(pairs ...string) string {
	parts := []string{}
	for i := 0; i+1 < len(pairs); i += 2 {
		parts = append(parts, sSoft.Render(pairs[i])+" "+sDim.Render(pairs[i+1]))
	}
	return "  " + strings.Join(parts, sDim.Render("  │  "))
}

// truncate cuts s to n display cells with an ellipsis.
func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= n {
		return s
	}
	r := []rune(s)
	for len(r) > 0 && lipgloss.Width(string(r))+1 > n {
		r = r[:len(r)-1]
	}
	return string(r) + "…"
}

// wrap breaks plain text into lines of at most n cells on spaces.
func wrap(s string, n int) []string {
	if n < 10 {
		n = 10
	}
	var out []string
	for _, para := range strings.Split(s, "\n") {
		line := ""
		for _, w := range strings.Fields(para) {
			switch {
			case line == "":
				line = w
			case lipgloss.Width(line)+1+lipgloss.Width(w) <= n:
				line += " " + w
			default:
				out = append(out, line)
				line = w
			}
			for lipgloss.Width(line) > n {
				r := []rune(line)
				out = append(out, string(r[:n]))
				line = string(r[n:])
			}
		}
		out = append(out, line)
	}
	return out
}

// spinner frames: braille, as in the mock.
var spinFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
