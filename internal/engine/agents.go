package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
)

// AgentInfo is one agent the runner can launch (`python -m lab agents --json`).
// The runner is the source of truth: recipes no longer list agents.
type AgentInfo struct {
	Name          string   `json:"name"`
	SecretService string   `json:"secret_service"`
	SetupCommands []string `json:"setup_commands"`
	OwnWorkloadOK bool     `json:"own_workload_ok"`
}

var agentNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// Agents asks the engine for its agent table.
func Agents(ctx context.Context, root string) ([]AgentInfo, error) {
	var out bytes.Buffer
	code, err := ExecTo(ctx, root, []string{"agents", "--json"}, &out)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("engine agents: exit %d", code)
	}
	return parseAgents(out.Bytes())
}

func parseAgents(b []byte) ([]AgentInfo, error) {
	var v struct {
		Agents []AgentInfo `json:"agents"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("engine agents: %w", err)
	}
	var out []AgentInfo
	for _, a := range v.Agents {
		if agentNameRE.MatchString(a.Name) {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("engine agents: empty table")
	}
	return out, nil
}

// ValidAgentName checks the shape of a name; the engine decides if it exists.
func ValidAgentName(s string) bool { return agentNameRE.MatchString(s) }

// AgentNames returns the names, in engine order.
func AgentNames(as []AgentInfo) []string {
	n := make([]string, len(as))
	for i, a := range as {
		n[i] = a.Name
	}
	return n
}
