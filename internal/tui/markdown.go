package tui

import (
	"regexp"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	mdHeading = regexp.MustCompile(`^\s{0,3}#{1,6}\s+`)
	mdBullet  = regexp.MustCompile(`^(\s*)[-*+]\s+`)
)

// mdWord is one word of agent text with its markdown markers resolved.
type mdWord struct {
	styled string
	width  int
}

// renderMarkdown wraps agent text to width w and renders the markdown the
// agents write: **bold**, `code` (soft, without backticks), "- " bullets
// as "• ", headings without #. Anything else stays as written.
func renderMarkdown(text string, w int, base lipgloss.Style) []string {
	if w < 10 {
		w = 10
	}
	var out []string
	bold, code := false, false
	for _, para := range strings.Split(text, "\n") {
		indent, first := "", ""
		heading := false
		if m := mdHeading.FindString(para); m != "" {
			para, heading = para[len(m):], true
		}
		if m := mdBullet.FindStringSubmatch(para); m != nil {
			first = m[1] + "• "
			indent = strings.Repeat(" ", lipgloss.Width(first))
			para = para[len(m[0]):]
		}
		var words []mdWord
		for _, f := range strings.Fields(para) {
			var sb strings.Builder
			width := 0
			r := []rune(f)
			for i := 0; i < len(r); i++ {
				switch {
				case r[i] == '`':
					code = !code
					continue
				case !code && r[i] == '*' && i+1 < len(r) && r[i+1] == '*':
					bold = !bold
					i++
					continue
				}
				st := base
				switch {
				case code:
					st = sSoft
				case bold || heading:
					st = base.Bold(true)
				}
				sb.WriteString(st.Render(string(r[i])))
				width += lipgloss.Width(string(r[i]))
			}
			if width > 0 {
				words = append(words, mdWord{sb.String(), width})
			}
		}
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		line, lw, empty := first, lipgloss.Width(first), true
		for _, wd := range words {
			if !empty && lw+1+wd.width > w {
				out = append(out, line)
				line, lw, empty = indent, len(indent), true
			}
			if !empty {
				line += " "
				lw++
			}
			line += wd.styled
			lw += wd.width
			empty = false
		}
		out = append(out, line)
		// Markers never span paragraphs.
		bold, code = false, false
	}
	return out
}
