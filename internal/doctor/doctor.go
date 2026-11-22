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
	"sort"
	"strings"
	"syscall"
	"time"
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
}

// Agent credentials: sbx secret service per agent. Keep in sync with
// lab/sbx.py AGENTS; agents not listed here are not offered by burner yet.
var AgentServices = map[string]struct{ Service, Fix string }{
	"claude": {"anthropic", "sbx secret set anthropic"},
	"codex":  {"openai", "sbx secret set openai --oauth"},
	"devin":  {"devin", "sbx run devin <folder>   (sign in once)"},
}

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
}

// Check runs every check. It never fails fast: the user gets the full list.
func Check(ctx context.Context, o Options) []Result {
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
	var out []Result

	sbxOK := false
	if _, err := o.LookPath("sbx"); err != nil {
		out = append(out, Result{"sbx", "sbx installed", Fail, "sbx not found on PATH", "brew install docker/tap/sbx"})
	} else {
		v, err := o.Run(ctx, "sbx", "version")
		if err != nil {
			out = append(out, Result{"sbx", "sbx installed", Fail, firstLine(v, err), "reinstall sbx"})
		} else {
			sbxOK = true
			out = append(out, Result{"sbx", "sbx installed", OK, firstLine(v, nil), ""})
		}
	}

	// Host container runtime: Docker (or colima), else Apple container.
	// Needed only to save local images and pull private ones on the host.
	dockerUp := false
	if _, err := o.LookPath("docker"); err == nil {
		if v, err := o.Run(ctx, "docker", "info", "--format", "{{.ServerVersion}}"); err == nil {
			dockerUp = true
			out = append(out, Result{"runtime", "Host container runtime", OK, "docker " + firstLine(v, nil), ""})
		}
	}
	if !dockerUp {
		if _, err := o.LookPath("container"); err == nil {
			if _, err := o.Run(ctx, "container", "system", "status"); err == nil {
				out = append(out, Result{"runtime", "Host container runtime", OK, "Apple container", ""})
				dockerUp = true
			}
		}
	}
	// sbx builds a recipe's local kits with docker buildx on the host.
	if _, err := o.LookPath("docker"); err == nil {
		if _, err := o.Run(ctx, "docker", "buildx", "version"); err != nil {
			out = append(out, Result{"buildx", "Docker buildx (recipe kits)", Fail, "docker buildx is not available; sbx cannot build the recipe kits",
				"brew install docker-buildx && mkdir -p ~/.docker/cli-plugins && ln -sfn $(brew --prefix)/bin/docker-buildx ~/.docker/cli-plugins/docker-buildx"})
		} else {
			out = append(out, Result{"buildx", "Docker buildx (recipe kits)", OK, "available", ""})
		}
	} else {
		out = append(out, Result{"buildx", "Docker buildx (recipe kits)", Fail, "docker CLI not found; sbx needs docker buildx to build recipe kits", "brew install docker docker-buildx"})
	}
	if !dockerUp {
		out = append(out, Result{"runtime", "Host container runtime", Warn, "none running (needed only for local or private images)", "colima start, or container system start"})
	}

	for _, agent := range o.Agents {
		svc, ok := AgentServices[agent]
		if !ok {
			out = append(out, Result{"agent-" + agent, agentTitle(agent), Warn, "not supported by burner yet", ""})
			continue
		}
		if !sbxOK {
			out = append(out, Result{"agent-" + agent, agentTitle(agent), Warn, "cannot check without sbx", svc.Fix})
			continue
		}
		// Names only: `sbx secret ls --service S --quiet` prints secret names.
		v, err := o.Run(ctx, "sbx", "secret", "ls", "--service", svc.Service, "--quiet")
		switch {
		case err != nil:
			out = append(out, Result{"agent-" + agent, agentTitle(agent), Warn, "could not list secrets: " + firstLine(v, err), svc.Fix})
		case strings.TrimSpace(v) == "":
			out = append(out, Result{"agent-" + agent, agentTitle(agent), Warn, "no credential stored", svc.Fix})
		default:
			out = append(out, Result{"agent-" + agent, agentTitle(agent), OK, "credential stored (" + svc.Service + ")", ""})
		}
	}

	if _, err := o.LookPath("gh"); err != nil {
		out = append(out, Result{"git-login", "GitHub login", Warn, "gh not found (needed only for private repos)", "brew install gh && gh auth login"})
	} else if v, err := o.Run(ctx, "gh", "auth", "status", "--active"); err != nil {
		out = append(out, Result{"git-login", "GitHub login", Warn, "not signed in (needed only for private repos)", "gh auth login"})
	} else {
		_ = v
		out = append(out, Result{"git-login", "GitHub login", OK, "signed in", ""})
	}

	if home, err := os.UserHomeDir(); err == nil {
		if logins := RegistryLogins(home); len(logins) > 0 {
			out = append(out, Result{"registry-login", "Registry logins", OK, strings.Join(logins, ", "), ""})
		} else {
			out = append(out, Result{"registry-login", "Registry logins", OK, "none (needed only for private images: docker login <registry>)", ""})
		}
	}

	if o.DiskPath != "" {
		if gb, err := freeGB(o.DiskPath); err == nil {
			level, fix := OK, ""
			if gb < o.MinDiskGB {
				level, fix = Warn, "free disk space (images and kits need ~10 GB)"
			}
			out = append(out, Result{"disk", "Free disk", level, fmt.Sprintf("%.0f GB free", gb), fix})
		}
	}
	return out
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
