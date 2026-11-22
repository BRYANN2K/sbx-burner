// Package sanitize cleans agent-controlled text before burner shows it.
// The agent runs with full trust inside the sandbox, so anything it writes
// (questions, choices, messages, tool summaries) is untrusted on the
// user's terminal: escape sequences could move the cursor, rewrite earlier
// lines or write the clipboard (OSC 52).
package sanitize

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxField is the default cap for one rendered field.
const MaxField = 4096

// MaxChoices caps the number of choices shown for one question.
const MaxChoices = 64

// Text removes ANSI/OSC/DCS escape sequences and control characters
// (newline and tab kept), drops invalid UTF-8, and caps the length in bytes
// without cutting a rune. Truncation is marked with "…".
func Text(s string, max int) string {
	if max <= 0 {
		max = MaxField
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == 0x1b: // ESC
			i = skipEscape(s, i)
			continue
		case c == 0x9b: // 8-bit CSI
			i = skipCSI(s, i+1)
			continue
		case c == 0x9d || c == 0x90 || c == 0x9e || c == 0x9f: // 8-bit OSC, DCS, PM, APC
			i = skipString(s, i+1)
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if r == utf8.RuneError && size == 1 {
			continue
		}
		if r == '\n' || r == '\t' {
			b.WriteRune(r)
			continue
		}
		if unicode.IsControl(r) || r == ' ' || r == ' ' || isBidi(r) {
			continue
		}
		b.WriteRune(r)
	}
	return truncate(b.String(), max)
}

// Line is Text for single-line fields: newlines become spaces.
func Line(s string, max int) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(Text(s, max), "\t", " ")), " ")
}

// Choices cleans and caps a choice list.
func Choices(in []string) []string {
	if len(in) > MaxChoices {
		in = in[:MaxChoices]
	}
	out := make([]string, 0, len(in))
	for _, c := range in {
		if c = Line(c, 200); c != "" {
			out = append(out, c)
		}
	}
	return out
}

func skipEscape(s string, i int) int {
	if i+1 >= len(s) {
		return len(s)
	}
	switch s[i+1] {
	case '[':
		return skipCSI(s, i+2)
	case ']', 'P', '^', '_', 'X': // OSC, DCS, PM, APC, SOS
		return skipString(s, i+2)
	default:
		return i + 2 // two-byte sequence (ESC 7, ESC c, …)
	}
}

// skipCSI skips parameters and intermediates up to the final byte 0x40–0x7e.
func skipCSI(s string, i int) int {
	for ; i < len(s); i++ {
		if s[i] >= 0x40 && s[i] <= 0x7e {
			return i + 1
		}
	}
	return len(s)
}

// skipString skips until BEL, ST (ESC \) or 8-bit ST (0x9c).
func skipString(s string, i int) int {
	for ; i < len(s); i++ {
		switch {
		case s[i] == 0x07 || s[i] == 0x9c:
			return i + 1
		case s[i] == 0x1b && i+1 < len(s) && s[i+1] == '\\':
			return i + 2
		}
	}
	return len(s)
}

func isBidi(r rune) bool {
	return (r >= '‪' && r <= '‮') || (r >= '⁦' && r <= '⁩') || r == '‎' || r == '‏'
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max - len("…")
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
