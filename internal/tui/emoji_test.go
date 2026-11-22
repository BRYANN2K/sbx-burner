package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Bryan's rule: no emoji anywhere in the TUI. Text, box drawing and
// braille only. These dingbats are text symbols, allowed: ✓ ✗ ❯.
var allowed = map[rune]bool{'✓': true, '✗': true, '❯': true}

func isEmoji(r rune) bool {
	if allowed[r] {
		return false
	}
	switch {
	case r >= 0x1F000 && r <= 0x1FAFF, // pictographs, emoticons, transport, flags…
		r >= 0x2600 && r <= 0x27BF, // misc symbols and dingbats
		r >= 0x2B00 && r <= 0x2BFF, // arrows and stars with emoji forms
		r >= 0x231A && r <= 0x231B, r == 0x2328, r == 0x23CF,
		r >= 0x23E9 && r <= 0x23FA,
		r == 0xFE0F, r == 0x200D, r == 0x20E3, // emoji presentation, ZWJ, keycap
		r == 0x3030, r == 0x303D, r == 0x3297, r == 0x3299:
		return true
	}
	return false
}

func checkNoEmoji(t *testing.T, where, s string) {
	t.Helper()
	for i, line := range strings.Split(s, "\n") {
		for _, r := range line {
			if isEmoji(r) {
				t.Errorf("%s:%d: emoji %q (U+%04X)", where, i+1, string(r), r)
			}
		}
	}
}

func TestNoEmojiInSourcesAndScreens(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	main, _ := filepath.Glob("../../cmd/burner/*.go")
	goldens, _ := filepath.Glob("testdata/*.golden")
	if len(goldens) == 0 {
		t.Fatal("no golden screens found")
	}
	files = append(append(files, main...), goldens...)
	for _, f := range files {
		if strings.HasSuffix(f, "emoji_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		checkNoEmoji(t, f, string(b))
	}
}

func TestEmojiDetector(t *testing.T) {
	for _, r := range []rune{0x1F4C1, 0x1F525, 0x2705, 0x26A0, 0x2B50, 0xFE0F} {
		if !isEmoji(r) {
			t.Errorf("U+%04X not detected", r)
		}
	}
	for _, r := range "✓✗❯›◆⊘■⠋⣿─│╭" {
		if isEmoji(r) {
			t.Errorf("%q flagged", r)
		}
	}
}
