package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"syscall"

	"github.com/BRYANN2K/sbx-burner/internal/acp"
)

var agentNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// modelsCache is where burner keeps the last model list per agent.
func modelsCache(agent string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".burner", "cache", "acp-models-"+agent+".json"), nil
}

// cacheModels copies a run's acp-models.json into the cache (best effort).
func cacheModels(src string) {
	fi, err := os.Lstat(src)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > 1<<20 {
		return
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		return
	}
	var m acp.Models
	if json.Unmarshal(raw, &m) != nil || !agentNameRE.MatchString(m.Agent) {
		return
	}
	dst, err := modelsCache(m.Agent)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(dst), 0o700)
	_ = os.WriteFile(dst, raw, 0o600)
}

// burner models --agent A [--json]
func cmdModels(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("models", flag.ContinueOnError)
	fs.SetOutput(stderr)
	agent := fs.String("agent", "", "")
	asJSON := fs.Bool("json", false, "")
	if fs.Parse(args) != nil || *agent == "" || !agentNameRE.MatchString(*agent) {
		fmt.Fprintln(stderr, "usage: burner models --agent A [--json]")
		return exitUsage
	}
	if _, ok := acp.Profiles[*agent]; !ok {
		return fail(stderr, exitUsage, fmt.Errorf("%s is not driven over ACP yet (burner acp agents)", *agent))
	}
	path, err := modelsCache(*agent)
	if err != nil {
		return fail(stderr, exitFailed, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if *asJSON {
			fmt.Fprintf(stdout, "{\"agent\":%q,\"values\":[],\"known\":false}\n", *agent)
			return exitOK
		}
		fmt.Fprintf(stderr, "No model list yet for %s. The agent sends it at the start of an ACP run:\n  burner run <recipe> --acp --agent %s ...\n", *agent, *agent)
		return exitNotReady
	}
	var m acp.Models
	if err := json.Unmarshal(raw, &m); err != nil {
		return fail(stderr, exitFailed, err)
	}
	if *asJSON {
		out, _ := json.Marshal(struct {
			acp.Models
			Known bool `json:"known"`
		}{m, true})
		fmt.Fprintln(stdout, string(out))
		return exitOK
	}
	fmt.Fprintf(stdout, "%s models (seen %s):\n", m.Agent, m.Seen)
	for _, v := range m.Values {
		mark := " "
		if v.Value == m.Current {
			mark = "*"
		}
		fmt.Fprintf(stdout, " %s %-24s %s\n", mark, v.Value, v.Name)
	}
	return exitOK
}

// burner acp agents [--json]
func cmdACP(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "agents" {
		fmt.Fprintln(stderr, "usage: burner acp agents [--json]")
		return exitUsage
	}
	names := make([]string, 0, len(acp.Profiles))
	for n := range acp.Profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(args) > 1 && args[1] == "--json" {
		out, _ := json.Marshal(map[string]any{"acp_agents": names})
		fmt.Fprintln(stdout, string(out))
		return exitOK
	}
	for _, n := range names {
		fmt.Fprintln(stdout, n)
	}
	return exitOK
}

// burner acp-bridge (internal): started by the runner for `run --acp`.
func cmdACPBridge(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("acp-bridge", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o acp.BridgeOptions
	fs.StringVar(&o.Agent, "agent", "", "")
	fs.StringVar(&o.Permission, "permission", "auto", "")
	fs.StringVar(&o.Model, "model", "", "")
	fs.StringVar(&o.Prompt, "prompt", "", "")
	fs.StringVar(&o.Cwd, "cwd", "", "")
	fs.StringVar(&o.Transcript, "transcript", "", "")
	fs.BoolVar(&o.Unattended, "unattended", false, "")
	if fs.Parse(args) != nil || o.Agent == "" || o.Prompt == "" || o.Cwd == "" || fs.NArg() == 0 {
		fmt.Fprintln(stderr, "usage: burner acp-bridge --agent A --cwd DIR --prompt TEXT [--model ID] [--permission auto|ask] [--transcript FILE] [--unattended] -- SBX-EXEC-ARGV")
		return exitUsage
	}
	o.Argv = fs.Args()
	o.In, o.Out = os.Stdin, os.Stdout
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return acp.RunBridge(ctx, o)
}
