package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/BRYANN2K/sbx-burner/internal/engine"
	"github.com/BRYANN2K/sbx-burner/internal/events"
)

func activityLive(t *testing.T, evs []events.Event) model {
	t.Helper()
	eng := &fakeEngine{events: evs, block: make(chan struct{})}
	m := testModel(t, eng)
	m.w, m.h = 150, 44
	m.plan = newPlan(engine.RunOptions{Recipe: "devsecops/secrets-scan", Agent: "claude", ACP: true, Model: "claude-mythos-5-2", Permission: "auto", RunsDir: "/runs", Target: "/home/tester/burner-test/leaky-repo"})
	m.plan.loading = false
	m.plan.text = "Plan for devsecops/secrets-scan\n  sandbox:   lab-secrets-scan-194453\n  allow:     api.anthropic.com:443\n\nSteps:\n  1. create: x\n  2. agent: z\n"
	m.scr = scrPlan
	nm, cmd := m.Update(keyMsg("enter"))
	m = nm.(model)
	for i := 0; i < len(evs) && cmd != nil; i++ {
		msg := cmd()
		if b, ok := msg.(tea.BatchMsg); ok {
			msg = b[0]()
		}
		nm, cmd = m.Update(msg)
		m = nm.(model)
	}
	t.Cleanup(func() { close(eng.block) })
	return m
}

// The mock's data: Bryan's Claude Mythos secrets-scan run, with Codex's
// narration lines.
func activityEvents(run string) []events.Event {
	act := func(id, desc, cmd, status string) events.Event {
		return events.Event{Type: "agent.tool", Tool: "execute", ID: id, Summary: desc, Detail: cmd, Status: status, RunID: run}
	}
	out := func(id, lines string) events.Event {
		return events.Event{Type: "agent.tool", Tool: "output", ID: id, Summary: lines, RunID: run}
	}
	return []events.Event{
		{Type: "step", Name: "create", Status: "start", RunID: run},
		{Type: "step", Name: "create", Status: "ok", RunID: run},
		{Type: "step", Name: "agent", Status: "start", RunID: run},
		{Type: "agent.message", Agent: "claude", Text: "I'll read the task and the secrets-triage workflow first, then scan only the authorized target and write the required evidence artifacts.", RunID: run},
		act("t1", "Read skills, schema, and inspect workspace and target", "cat .claude/skills/secrets-triage/SKILL.md .claude/skills/evidence-hygiene/SKILL.md .lab/evidence.schema.json; ls -la . evidence .lab", "pending"),
		act("t1", "Read skills, schema, and inspect workspace and target", "cat .claude/skills/secrets-triage/SKILL.md .claude/skills/evidence-hygiene/SKILL.md .lab/evidence.schema.json; ls -la . evidence .lab", "completed"),
		out("t1", "/usr/bin/jq\n/usr/bin/git\nLAB_TARGET_KIND=path\nLAB_TARGET_PATH=/home/agent/target"),
		act("t2", "Inspect target layout and tool versions", "cat .lab/tools-installed.tsv; gitleaks version; trufflehog --version 2>&1", "completed"),
		{Type: "agent.tool", Tool: "thinking", Summary: "checking the target is a git repo before scanning history", RunID: run},
		act("t3", "Run gitleaks and trufflehog scans, show redacted results and history", "W=$PWD; A=$W/evidence/artifacts; mkdir -p $A; T=/home/agent/target; R=$T/leaky-repo cd $R gitleaks git --redact --report-format json --report-path $A/gitleaks.json --exit-code 1 .", "completed"),
		out("t3", "packs: 0\nsize-pack: 0\nprune-packable: 0\ngarbage: 0"),
		{Type: "agent.message", Agent: "claude", Text: "Gitleaks found three historical entries: an AWS key pair and a test-only generic API key. Trufflehog independently found the AWS access key ID.", RunID: run},
		{Type: "finding", ID: "aws-key-pair-c5a94c0", Severity: "critical", Status: "candidate", Title: ".env:2-3 @ c5a94c0", RunID: run},
		act("t4", "Mask remaining trufflehog fields and recheck evidence", "E=$PWD/evidence; A=$E/artifacts; jq -c '.SecretParts|=with_entries(.value|=m)' $A/trufflehog.jsonl", "in_progress"),
	}
}

func TestRunScreenActivity(t *testing.T) {
	run := "20261122-194453-secrets-scan"
	m := activityLive(t, activityEvents(run))
	l := m.live
	if n, done, failed := l.activity(); n != 4 || done != 3 || failed != 0 {
		t.Fatalf("activity %d %d %d", n, done, failed)
	}
	golden(t, "run-activity", m)
	// o opens the latest action with output (t3), O opens every action.
	m = press(t, m, "o")
	golden(t, "run-activity-open", m)
	if v := m.View(); !strings.Contains(v, "│ garbage: 0") || strings.Contains(v, "│ LAB_TARGET_KIND") {
		t.Fatal("o did not open only the latest action with output")
	}
	m = press(t, m, "O")
	if !strings.Contains(m.View(), "│ LAB_TARGET_KIND=path") {
		t.Fatal("O did not open every action")
	}
	for _, k := range []string{"o", "open / close action", "O", "open all"} {
		if !strings.Contains(l.runHints(), k) {
			t.Fatalf("key bar lacks %q", k)
		}
	}
}

// An update with the same id updates the action (spinner -> ✓) instead of
// adding a line.
func TestActionUpdatesInPlace(t *testing.T) {
	l := newLive(engine.RunOptions{Agent: "claude", ACP: true}, fixedNow())
	l.add(events.Event{Type: "agent.tool", Tool: "execute", ID: "t1", Summary: "gitleaks git .", Status: "pending"})
	l.add(events.Event{Type: "agent.tool", Tool: "execute", ID: "t1", Summary: "Run gitleaks", Detail: "gitleaks git .", Status: "in_progress"})
	if len(l.log) != 1 || l.log[0].ev.Summary != "Run gitleaks" || actionDone(l.log[0].ev) {
		t.Fatalf("log %+v", l.log)
	}
	l.add(events.Event{Type: "agent.tool", Tool: "execute", ID: "t1", Summary: "Run gitleaks", Detail: "gitleaks git .", Status: "completed"})
	l.add(events.Event{Type: "agent.tool", Tool: "output", ID: "t1", Summary: "leaks found: 3"})
	l.add(events.Event{Type: "agent.tool", Tool: "output", ID: "nope", Summary: "orphan"})
	if len(l.log) != 1 || l.log[0].ev.Status != "completed" || strings.Join(l.log[0].output, "|") != "leaks found: 3" {
		t.Fatalf("log %+v", l.log)
	}
	m := testModel(t, &fakeEngine{})
	lines := strings.Join(l.renderEntry(m, l.log[0], 80), "\n")
	if !strings.Contains(lines, "✓ Run gitleaks") || !strings.Contains(lines, "$ gitleaks git .") || strings.Contains(lines, "leaks found") {
		t.Fatalf("closed action:\n%s", lines)
	}
}

func fixedNow() time.Time { return time.Date(2026, 11, 22, 19, 44, 53, 0, time.UTC) }
