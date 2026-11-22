// Package doctor checks what a run needs before anything starts: sbx, a
// container runtime, agent credentials and free disk. It never reads or
// prints secret values; credential checks list secret names only.
package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/BRYANN2K/sbx-burner/internal/engine"
)

// Level of a check result.
type Level string

const (
	OK   Level = "ok"
	Warn Level = "warn"
	Fail Level = "fail"
)

// Result of one check. Fix is a command the user can run, when there is one.
type Result struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Level  Level  `json:"level"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
	// Actions fix the line from burner (setup and Doctor); the first is the
	// default, more than one are choices.
	Actions []Action `json:"actions,omitempty"`
}

func res(id, title string, l Level, detail, fix string) Result {
	return Result{ID: id, Title: title, Level: l, Detail: detail, Fix: fix}
}

// Agent credentials: sbx secret service per agent. Keep in sync with
// lab/sbx.py AGENTS; agents not listed here are not offered by burner yet.
var AgentServices = map[string]struct{ Service, Fix string }{
	"claude": {"anthropic", "sbx secret set anthropic"},
	"codex":  {"openai", "sbx secret set openai --oauth"},
	"devin":  {"devin", "sbx run devin <folder>   (sign in once)"},
	"cursor": {"cursor", "sbx secret set cursor --oauth"},
	// OpenCode keeps its providers in its own config; burner checks the
	// stored OpenAI credential it uses through sbx.
	"opencode": {"openai", "sbx run opencode <folder>   (set the providers in OpenCode)"},
}

// KnownAgents returns burner's own agent names, sorted; used only when the
// engine's agent table is unavailable.
func KnownAgents() []string {
	names := make([]string, 0, len(AgentServices))
	for a := range AgentServices {
		names = append(names, a)
	}
	sort.Strings(names)
	return names
}

// SbxLoginCommand signs the user in to Docker Sandboxes.
const SbxLoginCommand = "sbx login"

// Runner executes a command and returns combined output. Tests replace it.
type Runner func(ctx context.Context, name string, args ...string) (string, error)

// ExecRunner runs real commands with a timeout.
func ExecRunner(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// Options for Check.
type Options struct {
	Run       Runner
	LookPath  func(string) (string, error)
	DiskPath  string
	MinDiskGB float64
	Agents    []string
	// GOOS picks the install commands ("" : this machine's).
	GOOS string
	// Exists reports whether a file exists (nil : os.Stat). Used for the
	// Homebrew prefixes, Docker Desktop's app and /etc/os-release.
	Exists func(string) bool
	// ReadFile reads /etc/os-release (nil : os.ReadFile).
	ReadFile func(string) ([]byte, error)
}

// Check runs every check. It never fails fast: the user gets the full list.
// Machine lines come in install order, each with the actions that fix it.
func Check(ctx context.Context, o Options) []Result {
	real := o.LookPath == nil
	if o.Run == nil {
		o.Run = ExecRunner
	}
	if o.LookPath == nil {
		o.LookPath = exec.LookPath
	}
	if o.MinDiskGB == 0 {
		o.MinDiskGB = 10
	}
	if len(o.Agents) == 0 {
		o.Agents = []string{"claude", "codex", "devin"}
	}
	if o.GOOS == "" {
		o.GOOS = runtime.GOOS
	}
	if o.Exists == nil {
		o.Exists = func(p string) bool { _, err := os.Stat(p); return err == nil }
	}
	if o.ReadFile == nil {
		o.ReadFile = os.ReadFile
	}
	if real {
		addBrewPath(o.Exists)
	}
	env := detectEnv(o)
	has := func(name string) bool { _, err := o.LookPath(name); return err == nil }
	var out []Result

	if o.GOOS == "darwin" {
		if env.brew == "" {
			out = append(out, with(res("brew", "Homebrew", Fail, "not installed", "see https://brew.sh"), env.brewInstall()))
		} else {
			out = append(out, res("brew", "Homebrew", OK, "installed", ""))
		}
	}

	sbxOK := false
	if !has("sbx") {
		out = append(out, with(res("sbx", "sbx installed", Fail, "sbx not found on PATH", "brew install docker/tap/sbx"), env.sbxInstall(false)))
	} else {
		v, err := o.Run(ctx, "sbx", "version")
		if err != nil {
			out = append(out, with(res("sbx", "sbx installed", Fail, firstLine(v, err), "reinstall sbx"), env.sbxInstall(true)))
		} else {
			sbxOK = true
			out = append(out, res("sbx", "sbx installed", OK, firstLine(v, nil), ""))
		}
	}

	// Host container runtime: Docker (Docker Desktop or colima), else Apple
	// container. sbx builds the recipe kits through it.
	dockerUp := false
	if has("docker") {
		if v, err := o.Run(ctx, "docker", "info", "--format", "{{.ServerVersion}}"); err == nil {
			dockerUp = true
			out = append(out, res("runtime", "Host container runtime", OK, "docker "+firstLine(v, nil), ""))
		}
	}
	if !dockerUp && has("container") {
		if _, err := o.Run(ctx, "container", "system", "status"); err == nil {
			out = append(out, res("runtime", "Host container runtime", OK, "Apple container", ""))
			dockerUp = true
		}
	}
	if !dockerUp {
		detail := "none running (needed to build recipe kits)"
		var installed []string
		if has("colima") {
			installed = append(installed, "colima")
		}
		if o.Exists("/Applications/Docker.app") {
			installed = append(installed, "docker-desktop")
		}
		if has("container") {
			installed = append(installed, "container")
		}
		if len(installed) > 0 {
			detail = "installed, not running"
		}
		out = append(out, with(res("runtime", "Host container runtime", Warn, detail, "colima start, or container system start"), env.runtimeActions(installed)...))
	}

	// sbx builds a recipe's local kits with docker buildx on the host.
	switch {
	case !has("docker"):
		out = append(out, with(res("buildx", "Docker buildx (recipe kits)", Fail, "docker CLI not found; sbx needs docker buildx to build recipe kits", "brew install docker docker-buildx"), env.buildxInstall(true)))
	default:
		if _, err := o.Run(ctx, "docker", "buildx", "version"); err != nil {
			out = append(out, with(res("buildx", "Docker buildx (recipe kits)", Fail, "docker buildx is not available; sbx cannot build the recipe kits",
				"brew install docker-buildx && mkdir -p ~/.docker/cli-plugins && ln -sfn $(brew --prefix)/bin/docker-buildx ~/.docker/cli-plugins/docker-buildx"), env.buildxInstall(false)))
		} else {
			out = append(out, res("buildx", "Docker buildx (recipe kits)", OK, "available", ""))
		}
	}

	if env.tool(o, "git") {
		out = append(out, res("git", "git", OK, "installed", ""))
	} else {
		out = append(out, with(res("git", "git", Fail, "not installed", "brew install git"), env.pkgInstall("git", "git", "https://git-scm.com/downloads")))
	}
	out = append(out, pythonCheck(ctx, o, env))

	if sbxOK {
		login, policy := policyCheck(ctx, o.Run, env)
		out = append(out, login, policy)
	}

	for _, agent := range o.Agents {
		svc, ok := AgentServices[agent]
		if !ok {
			out = append(out, res("agent-"+agent, agentTitle(agent), Warn, "not supported by burner yet", ""))
			continue
		}
		if !sbxOK {
			out = append(out, res("agent-"+agent, agentTitle(agent), Warn, "cannot check without sbx", svc.Fix))
			continue
		}
		// Names only: `sbx secret ls --service S --quiet` prints secret names.
		v, err := o.Run(ctx, "sbx", "secret", "ls", "--service", svc.Service, "--quiet")
		switch {
		case err != nil:
			out = append(out, res("agent-"+agent, agentTitle(agent), Warn, "could not list secrets: "+firstLine(v, err), svc.Fix))
		case strings.TrimSpace(v) == "":
			out = append(out, res("agent-"+agent, agentTitle(agent), Warn, "no credential stored", svc.Fix))
		default:
			out = append(out, res("agent-"+agent, agentTitle(agent), OK, "credential stored ("+svc.Service+")", ""))
		}
	}

	if !has("gh") {
		out = append(out, with(res("git-login", "GitHub login", Warn, "gh not found (needed only for private repos)", "brew install gh && gh auth login"), env.ghInstall()))
	} else if _, err := o.Run(ctx, "gh", "auth", "status", "--active"); err != nil {
		out = append(out, with(res("git-login", "GitHub login", Warn, "not signed in (needed only for private repos)", "gh auth login"),
			Action{Label: "sign in", Argv: []string{"gh", "auth", "login"}}))
	} else {
		out = append(out, res("git-login", "GitHub login", OK, "signed in", ""))
	}

	if home, err := os.UserHomeDir(); err == nil {
		if logins := RegistryLogins(home); len(logins) > 0 {
			out = append(out, res("registry-login", "Registry logins", OK, strings.Join(logins, ", "), ""))
		} else {
			out = append(out, res("registry-login", "Registry logins", OK, "none (needed only for private images: docker login <registry>)", ""))
		}
	}

	if o.DiskPath != "" {
		if gb, err := freeGB(o.DiskPath); err == nil {
			r := res("disk", "Free disk", OK, fmt.Sprintf("%.0f GB free", gb), "")
			if gb < o.MinDiskGB {
				r.Level, r.Fix = Warn, "free disk space (images and kits need ~10 GB)"
				r.Actions = []Action{{Label: "free space", Note: fmt.Sprintf("burner needs about %.0f GB for sandbox images and recipe kits", o.MinDiskGB)}}
			}
			out = append(out, r)
		}
	}
	return out
}

func with(r Result, a ...Action) Result {
	r.Actions = a
	return r
}

// Worst returns the most severe level in results.
func Worst(results []Result) Level {
	worst := OK
	for _, r := range results {
		if r.Level == Fail {
			return Fail
		}
		if r.Level == Warn {
			worst = Warn
		}
	}
	return worst
}

// AgentReady tells whether an agent passed its credential check.
func AgentReady(results []Result, agent string) bool {
	for _, r := range results {
		if r.ID == "agent-"+agent {
			return r.Level == OK
		}
	}
	return false
}

func agentTitle(agent string) string {
	switch agent {
	case "claude":
		return "Claude Code credential"
	case "codex":
		return "Codex credential"
	case "devin":
		return "Devin credential"
	case "cursor":
		return "Cursor credential"
	case "opencode":
		return "OpenCode credential"
	}
	return agent + " credential"
}

// firstLine shows a version string on success. On error it never echoes
// the command's output (it could hold a token); it reports the exit only.
func firstLine(s string, err error) string {
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return fmt.Sprintf("exit status %d", exit.ExitCode())
		}
		return "command failed"
	}
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if !versionLike.MatchString(s) {
		return "ok"
	}
	return s
}

// Only short version-looking strings are shown back to the user.
var versionLike = regexp.MustCompile(`^(?:[A-Za-z-]{1,20} )?(?:version )?v?\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9.]{1,20})?(?: [0-9a-f]{7,40})?$`)

// RegistryLogins lists registry host names from ~/.docker/config.json
// (names only; auth values are never read into a Result).
func RegistryLogins(home string) []string {
	raw, err := os.ReadFile(filepath.Join(home, ".docker", "config.json"))
	if err != nil {
		return nil
	}
	var cfg struct {
		Auths       map[string]json.RawMessage `json:"auths"`
		CredHelpers map[string]string          `json:"credHelpers"`
	}
	if json.Unmarshal(raw, &cfg) != nil {
		return nil
	}
	var out []string
	for h := range cfg.Auths {
		out = append(out, h)
	}
	for h := range cfg.CredHelpers {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func freeGB(path string) (float64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return float64(st.Bavail) * float64(st.Bsize) / 1e9, nil
}

// ApprovalResults turns the engine's mixin kit approvals into check lines:
// one per kit, with `burner approve --agent X` when it still needs one.
func ApprovalResults(rows []engine.Approval) []Result {
	var out []Result
	for _, a := range rows {
		title := "Approval: " + a.Agent + " kit"
		switch {
		case a.Error != "":
			out = append(out, res("approval-"+a.Agent, title, Warn, "could not check: "+a.Error, "burner approve --agent "+a.Agent))
		case a.Approved:
			out = append(out, res("approval-"+a.Agent, title, OK, "approved", ""))
		default:
			var hosts []string
			for _, ds := range a.Missing {
				hosts = append(hosts, ds...)
			}
			sort.Strings(hosts)
			out = append(out, res("approval-"+a.Agent, title, Warn, "needs approval: "+strings.Join(hosts, ", "), "burner approve --agent "+a.Agent))
		}
	}
	return out
}

// ApprovalsNeeded lists the agents whose kit still needs an approval.
func ApprovalsNeeded(results []Result) []string {
	var out []string
	for _, r := range results {
		if strings.HasPrefix(r.ID, "approval-") && r.Level != OK {
			out = append(out, strings.TrimPrefix(r.ID, "approval-"))
		}
	}
	return out
}

// PolicyInitCommand sets sbx's global network policy to deny by default.
// It applies to every sbx sandbox on this machine, so burner runs it only
// when the user asks.
const PolicyInitCommand = "sbx policy init deny-all"

// policyCheck reads sbx's policy rules. It returns the sign-in line and
// the policy line: a global network rule that denies everything by default
// means the policy is initialized.
func policyCheck(ctx context.Context, run Runner, env machineEnv) (Result, Result) {
	login := res("sbx-login", "Docker Sandboxes sign-in", OK, "signed in", "")
	r := Result{ID: "policy", Title: "Global network policy"}
	initAction := Action{Label: "run", Argv: strings.Fields(PolicyInitCommand), Note: "applies to every sbx sandbox on this " + env.machine() + ", not only burner's"}
	out, err := run(ctx, "sbx", "policy", "ls", "--json")
	if err != nil {
		if strings.Contains(out, "not signed in") || strings.Contains(out, "sbx login") {
			login = with(res("sbx-login", "Docker Sandboxes sign-in", Warn, "not signed in", SbxLoginCommand),
				Action{Label: "sign in", Argv: strings.Fields(SbxLoginCommand), Note: "shows a device code: open the link and enter it"})
			r.Level, r.Detail, r.Fix = Warn, "sign in to Docker Sandboxes first", SbxLoginCommand
			return login, r
		}
		r.Level, r.Detail, r.Fix, r.Actions = Warn, "could not read: "+firstLine(out, err), PolicyInitCommand, []Action{initAction}
		return login, r
	}
	var v struct {
		Rules []struct {
			Scope        string   `json:"scope"`
			AppliesTo    string   `json:"applies_to"`
			ResourceType string   `json:"resource_type"`
			Decision     string   `json:"decision"`
			Resources    []string `json:"resources"`
			Status       string   `json:"status"`
		} `json:"rules"`
	}
	if json.Unmarshal([]byte(out), &v) != nil {
		r.Level, r.Detail, r.Fix, r.Actions = Warn, "could not read sbx policy ls --json", PolicyInitCommand, []Action{initAction}
		return login, r
	}
	for _, rule := range v.Rules {
		if rule.Scope == "global" && rule.AppliesTo == "all" && rule.ResourceType == "network" && rule.Decision == "deny" && rule.Status != "inactive" {
			for _, res := range rule.Resources {
				if res == "**" {
					r.Level, r.Detail = OK, "deny-all"
					return login, r
				}
			}
		}
	}
	r.Level, r.Detail, r.Fix, r.Actions = Warn, "not initialized", PolicyInitCommand, []Action{initAction}
	return login, r
}
