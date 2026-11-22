package engine

import "testing"

func TestParseAgentsKeepsValidNamesInOrder(t *testing.T) {
	got, err := parseAgents([]byte(`{"agents":[{"name":"claude","secret_service":"anthropic"},{"name":"Bad Name\u001b"},{"name":"codex","own_workload_ok":true}]}`))
	if err != nil || len(got) != 2 || got[0].Name != "claude" || got[1].Name != "codex" || !got[1].OwnWorkloadOK {
		t.Fatalf("got %+v err %v", got, err)
	}
	if _, err := parseAgents([]byte(`{"agents":[]}`)); err == nil {
		t.Fatal("empty table must fail")
	}
}
