package sanitize

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestStripsOSC52Clipboard(t *testing.T) {
	in := "Proceed?\x1b]52;c;cm0gLXJmIH4K\x07 yes"
	if got := Text(in, 0); got != "Proceed? yes" {
		t.Fatalf("got %q", got)
	}
	in = "x\x1b]52;c;cm0gLXJmIH4K\x1b\\y"
	if got := Text(in, 0); got != "xy" {
		t.Fatalf("ST-terminated OSC kept: %q", got)
	}
}

func TestStripsCursorMovesAndColors(t *testing.T) {
	in := "safe\x1b[2A\x1b[2K\x1b[31mfake ok\x1b[0m"
	if got := Text(in, 0); got != "safefake ok" {
		t.Fatalf("got %q", got)
	}
	if got := Text("a\x9b2Kb\x9d0;title\x9cc", 0); got != "abc" {
		t.Fatalf("8-bit sequences kept: %q", got)
	}
}

func TestDropsControlAndBidi(t *testing.T) {
	in := "a\rb\x08c\x00d‮evil⁦e\nf"
	if got := Text(in, 0); got != "abcdevile\nf" {
		t.Fatalf("got %q", got)
	}
}

func TestCapsLengthOnRuneBoundary(t *testing.T) {
	in := strings.Repeat("é", 5000)
	got := Text(in, 101)
	if len(got) > 101 || !utf8.ValidString(got) || !strings.HasSuffix(got, "…") {
		t.Fatalf("len=%d valid=%v", len(got), utf8.ValidString(got))
	}
}

func TestChoicesCapped(t *testing.T) {
	in := make([]string, 100)
	for i := range in {
		in[i] = "opt\x1b[1m"
	}
	in[3] = "\x1b]52;c;x\x07"
	out := Choices(in)
	if len(out) != MaxChoices-1 || out[0] != "opt" {
		t.Fatalf("len=%d first=%q", len(out), out[0])
	}
}

func TestLineFoldsNewlines(t *testing.T) {
	if got := Line("ls\n  -la\tfoo", 0); got != "ls -la foo" {
		t.Fatalf("got %q", got)
	}
}
