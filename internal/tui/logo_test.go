package tui

import (
	"strings"
	"testing"
	"time"
)

func TestSparksStayInRegionOnEmptyDots(t *testing.T) {
	for seed := int64(1); seed < 20; seed++ {
		for n := 0; n < 200; n++ {
			lit := sparks(seed, n)
			if len(lit) != sparksPerFrame {
				t.Fatalf("frame %d: %d sparks", n, len(lit))
			}
			for _, d := range lit {
				x, y := d[0], d[1]
				if x < sparkX0 || x > sparkX1 || y < sparkY0 || y > sparkY1 {
					t.Fatalf("spark (%d,%d) outside the region", x, y)
				}
				if baseHasDot(x, y) {
					t.Fatalf("spark (%d,%d) on a dot of the base", x, y)
				}
			}
		}
	}
	// The base itself never changes.
	before := strings.Join(logoBase, "\n")
	_ = logoFrame(true, sparks(3, 9))
	if strings.Join(logoBase, "\n") != before {
		t.Fatal("drawing a frame changed the base")
	}
}

func TestBlinkFrameChangesOnlyTheEyes(t *testing.T) {
	if len(logoEyesClosed) != len(logoBase) {
		t.Fatal("eyes_closed has another height")
	}
	changed := 0
	for r := range logoBase {
		a, b := []rune(logoBase[r]), []rune(logoEyesClosed[r])
		if len(a) != logoW || len(b) != logoW {
			t.Fatalf("row %d is not %d cells", r, logoW)
		}
		for c := range a {
			if a[c] == b[c] {
				continue
			}
			changed++
			if r < 5 || r > 6 || c < 5 || c > 10 {
				t.Fatalf("blink changes cell (%d,%d), outside the eyes", r, c)
			}
		}
	}
	if changed == 0 {
		t.Fatal("the blink frame is the base")
	}
}

func TestBlinkTiming(t *testing.T) {
	var closedFor, gap time.Duration
	last := false
	var openedAt time.Duration
	for ts := time.Duration(0); ts < 2*time.Minute; ts += 10 * time.Millisecond {
		b := blinking(42, ts)
		if b {
			closedFor += 10 * time.Millisecond
		}
		if b && !last {
			if openedAt > 0 {
				gap = ts - openedAt
				if gap < blinkMin-blinkClosed-20*time.Millisecond || gap > blinkMax {
					t.Fatalf("blink gap %s outside [2.5 s, 5 s]", gap)
				}
			}
		}
		if !b && last {
			openedAt = ts
		}
		last = b
	}
	if closedFor == 0 {
		t.Fatal("never blinked in two minutes")
	}
}

func TestHeadFallsBackToOneLine(t *testing.T) {
	m := testModel(t, &fakeEngine{})
	if got := len(m.headLines()); got != len(logoBase)+4 { // box: border and padding
		t.Fatalf("head has %d lines, want the logo", got)
	}
	m.w = 30
	if got := m.headLines(); len(got) != 1 || !strings.Contains(got[0], "burner") {
		t.Fatalf("narrow head: %q", got)
	}
}
