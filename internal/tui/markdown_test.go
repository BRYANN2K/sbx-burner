package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func TestRenderMarkdown(t *testing.T) {
	got := renderMarkdown("**Caveats**\n- **Schema validation was manual.** Run `jsonschema` later.\n## Next\nplain", 40, sSoft)
	plain := make([]string, len(got))
	for i, l := range got {
		plain[i] = ansi.Strip(l)
	}
	want := []string{"Caveats", "• Schema validation was manual. Run", "  jsonschema later.", "Next", "plain"}
	if strings.Join(plain, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q", plain)
	}
	for _, l := range got {
		if w := len([]rune(ansi.Strip(l))); w > 40 {
			t.Fatalf("too wide: %q", l)
		}
	}
}
