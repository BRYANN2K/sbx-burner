package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
)

// AgentInfo is one agent the runner can launch (`python -m lab agents --json`).
// The runner is the source of truth: recipes no longer list agents.
type AgentInfo struct {
	Name          string   `json:"name"`
	SecretService string   `json:"secret_service"`
	SetupCommands []string `json:"setup_commands"`
	OwnWorkloadOK bool     `json:"own_workload_ok"`
	TUI           []string `json:"tui"` // the agent's own TUI command in the sandbox
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

// Approval is one mixin kit's credential approval in sbx (`lab approvals`).
type Approval struct {
	Agent    string              `json:"agent"`
	Kit      string              `json:"kit"`
	Approved bool                `json:"approved"`
	Missing  map[string][]string `json:"missing"`
	Error    string              `json:"error"`
}

// Approvals asks the engine which mixin kits still need an approval.
func Approvals(ctx context.Context, root string) ([]Approval, error) {
	var out bytes.Buffer
	code, err := ExecStreams(ctx, root, []string{"approvals", "--json"}, nil, &out, io.Discard)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("lab approvals exited %d", code)
	}
	var v struct {
		Approvals []Approval `json:"approvals"`
	}
	if out.Len() > 1<<20 || json.Unmarshal(out.Bytes(), &v) != nil {
		return nil, fmt.Errorf("lab approvals: unreadable output")
	}
	var ok []Approval
	for _, a := range v.Approvals {
		if agentNameRE.MatchString(a.Agent) {
			ok = append(ok, a)
		}
	}
	return ok, nil
}
