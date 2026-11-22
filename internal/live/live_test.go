package live

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/BRYANN2K/sbx-burner/internal/events"
)

func TestRenderFixture(t *testing.T) {
	raw, err := os.ReadFile("../../tests/fixtures/events/run.ndjson")
	if err != nil {
		t.Skip("fixture missing")
	}
	var buf bytes.Buffer
	st := &State{pending: map[string]events.Event{}, answered: map[string]bool{}, Findings: map[string]events.Event{}}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		e, err := events.Decode([]byte(line))
		if err != nil {
			t.Fatal(err)
		}
		handle(e, t.TempDir(), st, Options{Out: &buf})
	}
	out := buf.String()
	for _, want := range []string{"✓ create · sandbox lab-demo-103000", "› osv-scanner", "⊘ blocked example.com:443", "? a1: Login page found", "→ a1: no (user)", "→ a2: no answer (timeout)", "◆ F-1 proven", "■ done · exit 0"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestForgedAnswerIsFlagged(t *testing.T) {
	var buf bytes.Buffer
	st := &State{pending: map[string]events.Event{}, answered: map[string]bool{}, Findings: map[string]events.Event{}}
	v := "yes"
	handle(events.Event{Type: "answer", AskID: "a9", By: "forged", Value: &v}, t.TempDir(), st, Options{Out: &buf})
	summary(st, Options{Out: &buf})
	if !strings.Contains(buf.String(), "WARNING: the agent wrote its own answer to a9") || len(st.Forged) != 1 {
		t.Fatalf("not flagged:\n%s", buf.String())
	}
}

func TestToolLineIsOneTrimmedLineWithoutTheKind(t *testing.T) {
	if got := ToolLine("execute", "gitleaks git\n  --redact .", 80); got != "  › gitleaks git --redact ." {
		t.Fatalf("got %q", got)
	}
	long := ToolLine("execute", strings.Repeat("x", 300), 40)
	if n := len([]rune(long)); n != 40 || !strings.HasSuffix(long, "…") {
		t.Fatalf("not cut to width: %d %q", n, long)
	}
	if got := ToolLine("permission", "auto-allowed once", 80); got != "  › permission: auto-allowed once" {
		t.Fatalf("got %q", got)
	}
}
