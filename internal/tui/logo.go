package tui

import (
	"math/rand"
	"os"
	"strings"
	"time"
)

// logoBase is burner's logo (16×9 braille cells, 32×36 dots), validated
// by Bryan on 2026-11-22 (/tmp/msbx/mocks/logo/logo-16-spec.json). It never
// changes; the sparks are drawn on top of it.
var logoBase = []string{
	"⠀⠀⠀⠀⠀⠀⣀⣀⣀⡀⠀⠀⣀⠀⠸⠿",
	"⠀⠀⢀⣤⣶⣿⣿⡿⠿⠀⣤⡼⠿⠃⠀⠀",
	"⠀⣰⣿⡿⠛⠉⠀⢠⣤⡀⠛⠃⠀⠀⠸⠿",
	"⣰⣿⡟⠀⠀⢀⣀⣨⣏⣀⠀⠀⠸⠿⠇⠀",
	"⠛⠋⢀⣀⣾⡿⠿⠿⠿⠿⣿⣆⡀⠀⣶⣿",
	"⣶⣦⢸⣿⡇⢤⣄⠀⢀⣠⠄⣿⡿⢀⣿⣿",
	"⠸⣿⣦⠘⢧⣈⣉⣀⣈⣉⣠⠟⢀⣾⣿⠇",
	"⠀⠘⢿⣷⣤⣈⠉⠉⠉⠉⣀⣤⡀⠙⠃⠀",
	"⠀⠀⠀⠉⠻⠿⣿⣿⣿⣿⠿⠛⠉⠀⠀⠀",
}

// logoEyesClosed is the same frame with the eyes off, shown during a blink.
var logoEyesClosed = []string{
	"⠀⠀⠀⠀⠀⠀⣀⣀⣀⡀⠀⠀⣀⠀⠸⠿",
	"⠀⠀⢀⣤⣶⣿⣿⡿⠿⠀⣤⡼⠿⠃⠀⠀",
	"⠀⣰⣿⡿⠛⠉⠀⢠⣤⡀⠛⠃⠀⠀⠸⠿",
	"⣰⣿⡟⠀⠀⢀⣀⣨⣏⣀⠀⠀⠸⠿⠇⠀",
	"⠛⠋⢀⣀⣾⡿⠿⠿⠿⠿⣿⣆⡀⠀⣶⣿",
	"⣶⣦⢸⣿⡇⠀⠀⠀⠀⠀⠀⣿⡿⢀⣿⣿",
	"⠸⣿⣦⠘⢧⣀⣀⣀⣀⣀⣠⠟⢀⣾⣿⠇",
	"⠀⠘⢿⣷⣤⣈⠉⠉⠉⠉⣀⣤⡀⠙⠃⠀",
	"⠀⠀⠀⠉⠻⠿⣿⣿⣿⣿⠿⠛⠉⠀⠀⠀",
}

const (
	logoW = 16 // cells
	// Blink: eyes closed for blinkClosed at a random interval in
	// [blinkMin, blinkMax].
	blinkMin, blinkMax = 2500 * time.Millisecond, 5000 * time.Millisecond
	blinkClosed        = 240 * time.Millisecond
	// Sparks ("D · Étincelles"): every sparkEvery, sparksPerFrame random
	// dots light up inside the region, only where the base has no dot.
	sparkX0, sparkX1 = 17, 31 // dot columns, inclusive
	sparkY0, sparkY1 = 0, 15  // dot rows, inclusive
	sparksPerFrame   = 5
	sparkEvery       = 120 * time.Millisecond
)

// dotBit is the braille bit of dot (dx, dy) inside one cell.
var dotBit = [2][4]rune{{0x01, 0x02, 0x04, 0x40}, {0x08, 0x10, 0x20, 0x80}}

func logoCell(x, y int) (row, col int, bit rune) {
	return y / 4, x / 2, dotBit[x%2][y%4]
}

// baseHasDot reports whether the base logo lights dot (x, y).
func baseHasDot(x, y int) bool {
	row, col, bit := logoCell(x, y)
	r := []rune(logoBase[row])[col]
	return (r-0x2800)&bit != 0
}

// emptyDots lists the region's dots the base leaves dark.
var emptyDots = func() [][2]int {
	var out [][2]int
	for y := sparkY0; y <= sparkY1; y++ {
		for x := sparkX0; x <= sparkX1; x++ {
			if !baseHasDot(x, y) {
				out = append(out, [2]int{x, y})
			}
		}
	}
	return out
}()

// sparks picks the dots lit in spark frame n; the same seed and n give the
// same dots, so no state is kept between frames.
func sparks(seed int64, n int) [][2]int {
	rng := rand.New(rand.NewSource(seed*1_000_003 + int64(n)))
	idx := rng.Perm(len(emptyDots))
	out := make([][2]int, 0, sparksPerFrame)
	for _, i := range idx[:min(sparksPerFrame, len(idx))] {
		out = append(out, emptyDots[i])
	}
	return out
}

// blinking reports whether the eyes are closed at time t since start.
// Blink times come from the seed, so no state is kept.
func blinking(seed int64, t time.Duration) bool {
	rng := rand.New(rand.NewSource(seed ^ 0x5eed))
	at := time.Duration(0)
	for {
		at += blinkMin + time.Duration(rng.Int63n(int64(blinkMax-blinkMin)+1))
		if t < at {
			return false
		}
		if t < at+blinkClosed {
			return true
		}
	}
}

// logoFrame returns the logo lines (base, or eyes closed) with the given
// dots lit.
func logoFrame(eyesClosed bool, lit [][2]int) []string {
	src := logoBase
	if eyesClosed {
		src = logoEyesClosed
	}
	grid := make([][]rune, len(src))
	for i, l := range src {
		grid[i] = []rune(l)
	}
	for _, d := range lit {
		row, col, bit := logoCell(d[0], d[1])
		grid[row][col] |= bit
	}
	out := make([]string, len(grid))
	for i, r := range grid {
		out[i] = string(r)
	}
	return out
}

// animOn is false with NO_COLOR, TERM=dumb or BURNER_NO_ANIM=1.
func animOn() bool {
	return colorOn && os.Getenv("BURNER_NO_ANIM") != "1"
}

// logoLines is the logo for the current frame (the spinner's 80 ms tick
// drives it; a new spark set every sparkEvery).
func (m model) logoLines() []string {
	if !animOn() {
		return logoBase
	}
	t := time.Duration(m.frame) * 80 * time.Millisecond
	return logoFrame(blinking(m.seed, t), sparks(m.seed, int(t/sparkEvery)))
}

func lenVisible(s string) int { return len([]rune(strings.TrimSpace(s))) }
