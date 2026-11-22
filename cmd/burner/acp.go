package main

import (
	"bytes"
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
	"github.com/BRYANN2K/sbx-burner/internal/catalog"
	"github.com/BRYANN2K/sbx-burner/internal/engine"
	"github.com/BRYANN2K/sbx-burner/internal/sanitize"
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

// burner models --agent A [--json] [--refresh]
//
// Without --refresh it reads the cache a previous ACP run (or probe) wrote.
// --refresh asks the agent itself: the engine starts a throwaway sandbox,
// runs this binary's bridge in probe mode and always destroys it.
func cmdModels(ctx context.Context, catalogFlag string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("models", flag.ContinueOnError)
	fs.SetOutput(stderr)
	agent := fs.String("agent", "", "")
	asJSON := fs.Bool("json", false, "")
	refresh := fs.Bool("refresh", false, "")
	if fs.Parse(args) != nil || *agent == "" || !agentNameRE.MatchString(*agent) {
		fmt.Fprintln(stderr, "usage: burner models --agent A [--json] [--refresh]")
		return exitUsage
	}
	if _, ok := acp.Profiles[*agent]; !ok {
		return fail(stderr, exitUsage, fmt.Errorf("%s is not driven over ACP yet (burner acp agents)", *agent))
	}
	path, err := modelsCache(*agent)
	if err != nil {
		return fail(stderr, exitFailed, err)
	}
	if *refresh {
		if code, msg := probeModels(ctx, catalogFlag, *agent, path, stderr); code != exitOK {
			if *asJSON {
				out, _ := json.Marshal(map[string]any{"agent": *agent, "values": []any{}, "known": false, "error": msg})
				fmt.Fprintln(stdout, string(out))
				return code
			}
			fmt.Fprintln(stderr, "burner: "+msg)
			return code
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if *asJSON {
			fmt.Fprintf(stdout, "{\"agent\":%q,\"values\":[],\"known\":false}\n", *agent)
			return exitOK
		}
		fmt.Fprintf(stderr, "No model list yet for %s. Ask the agent (about a minute, in a throwaway sandbox):\n  burner models --agent %s --refresh\n", *agent, *agent)
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
	seen := m.Seen
	if m.Version != "" {
		seen += ", " + m.Agent + " " + m.Version
	}
	fmt.Fprintf(stdout, "%s models (seen %s):\n", m.Agent, seen)
	for _, v := range m.Values {
		mark := " "
		if v.Value == m.Current {
			mark = "*"
		}
		fmt.Fprintf(stdout, " %s %-24s %s\n", mark, v.Value, v.Name)
	}
	return exitOK
}

// probeModels runs `lab models --agent A --json` and writes its list to the
// cache. It returns burner's exit code and, on failure, one line to show.
func probeModels(ctx context.Context, catalogFlag, agent, cache string, stderr io.Writer) (int, string) {
	root, err := catalog.FindRoot(catalogFlag)
	if err != nil {
		return exitNotReady, err.Error()
	}
	var out bytes.Buffer
	code, err := engine.ExecStreams(ctx, root, []string{"models", "--agent", agent, "--json"}, nil, &out, stderr)
	if err != nil {
		return exitFailed, err.Error()
	}
	var res struct {
		acp.Models
		Error string `json:"error"`
	}
	if json.Unmarshal(bytes.TrimSpace(out.Bytes()), &res) != nil {
		return exitFailed, fmt.Sprintf("the engine gave no model list (exit %d)", code)
	}
	if code != 0 || res.Error != "" {
		msg := sanitize.Line(res.Error, 300)
		if msg == "" {
			msg = fmt.Sprintf("model probe failed (exit %d)", code)
		}
		if code == 0 {
			code = exitFailed
		}
		return code, msg
	}
	if res.Agent != agent {
		return exitFailed, "the probe answered for another agent"
	}
	for i := range res.Values {
		res.Values[i].Value = sanitize.Line(res.Values[i].Value, 120)
		res.Values[i].Name = sanitize.Line(res.Values[i].Name, 120)
	}
	raw, _ := json.MarshalIndent(res.Models, "", "  ")
	if err := os.MkdirAll(filepath.Dir(cache), 0o700); err != nil {
		return exitFailed, err.Error()
	}
	tmp, err := os.CreateTemp(filepath.Dir(cache), ".models-*")
	if err != nil {
		return exitFailed, err.Error()
	}
	_, werr := tmp.Write(raw)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmp.Name(), cache) != nil {
		os.Remove(tmp.Name())
		return exitFailed, "could not write the model cache"
	}
	return exitOK, ""
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
	fs.BoolVar(&o.Probe, "probe", false, "")
	if fs.Parse(args) != nil || o.Agent == "" || (o.Prompt == "" && !o.Probe) || o.Cwd == "" || fs.NArg() == 0 || (o.Probe && o.Transcript == "") {
		fmt.Fprintln(stderr, "usage: burner acp-bridge --agent A --cwd DIR (--prompt TEXT | --probe --transcript FILE) [--model ID] [--permission auto|ask] [--transcript FILE] [--unattended] -- SBX-EXEC-ARGV")
		return exitUsage
	}
	o.Argv = fs.Args()
	o.In, o.Out = os.Stdin, os.Stdout
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return acp.RunBridge(ctx, o)
}
