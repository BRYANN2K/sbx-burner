package doctor

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Action fixes one check line. burner runs Argv in its embedded terminal,
// only when the user presses enter. With no Argv, URL is the official page
// to follow, or Note says what to do by hand.
type Action struct {
	Label string   `json:"label"`
	Argv  []string `json:"argv,omitempty"`
	URL   string   `json:"url,omitempty"`
	Note  string   `json:"note,omitempty"`
}

// Official install commands, checked against each project's own docs:
//   - Homebrew: https://brew.sh
//   - sbx: https://github.com/docker/sbx-releases#install
//   - colima: https://github.com/abiosoft/colima#installation
//   - Docker Desktop: https://formulae.brew.sh/cask/docker-desktop
//   - Apple container: https://github.com/apple/container#install-or-upgrade
//   - buildx: the docker-buildx formula (plugin linked into ~/.docker/cli-plugins)
//   - gh: https://github.com/cli/cli#installation
const (
	brewInstallScript = `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`
	sbxAptInstall     = `curl -fsSL https://get.docker.com | sudo REPO_ONLY=1 sh && sudo apt-get install -y docker-sbx && sudo usermod -aG kvm "$USER"`
	sbxDocs           = "https://docs.docker.com/ai/sandboxes/"
	engineDocs        = "https://docs.docker.com/engine/install/"
	buildxDocs        = "https://github.com/docker/buildx#installing"
	ghLinuxDocs       = "https://github.com/cli/cli/blob/trunk/docs/install_linux.md"
	pythonDocs        = "https://www.python.org/downloads/"
)

// brewPrefixes are where the Homebrew installer puts brew.
var brewPrefixes = []string{"/opt/homebrew", "/usr/local", "/home/linuxbrew/.linuxbrew"}

// addBrewPath puts Homebrew's bin on burner's own PATH when brew is
// installed but the shell profile has not been reloaded yet (right after
// the installer), so the next checks and installs find it.
func addBrewPath(exists func(string) bool) {
	path := os.Getenv("PATH")
	for _, p := range brewPrefixes {
		bin := filepath.Join(p, "bin")
		if exists(filepath.Join(bin, "brew")) && !strings.Contains(":"+path+":", ":"+bin+":") {
			_ = os.Setenv("PATH", bin+string(os.PathListSeparator)+path)
			return
		}
	}
}

type machineEnv struct {
	goos   string
	brew   string // path to brew, "" when missing
	apt    bool   // Debian or Ubuntu with apt-get
	ubuntu bool
	clt    bool // macOS Command Line Tools (the /usr/bin/git and python3 shims need them)
}

func detectEnv(o Options) machineEnv {
	e := machineEnv{goos: o.GOOS}
	if p, err := o.LookPath("brew"); err == nil {
		e.brew = p
	} else {
		for _, pre := range brewPrefixes {
			if b := filepath.Join(pre, "bin", "brew"); o.Exists(b) {
				e.brew = b
				break
			}
		}
	}
	if e.goos == "linux" {
		if _, err := o.LookPath("apt-get"); err == nil {
			e.apt = true
		}
		if raw, err := o.ReadFile("/etc/os-release"); err == nil {
			for _, l := range strings.Split(string(raw), "\n") {
				if strings.TrimSpace(l) == "ID=ubuntu" {
					e.ubuntu = true
				}
			}
		}
	}
	if e.goos == "darwin" {
		e.clt = o.Exists("/Library/Developer/CommandLineTools/usr/bin/git") || o.Exists("/Applications/Xcode.app")
	}
	return e
}

func (e machineEnv) machine() string {
	if e.goos == "darwin" {
		return "Mac"
	}
	return "machine"
}

// tool reports whether name is usable. On macOS, /usr/bin/git and
// /usr/bin/python3 are shims that open an installer dialog until the
// Command Line Tools exist, so they count as missing without them.
func (e machineEnv) tool(o Options, name string) bool {
	p, err := o.LookPath(name)
	if err != nil {
		return false
	}
	if e.goos == "darwin" && strings.HasPrefix(p, "/usr/bin/") && !e.clt {
		return false
	}
	return true
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// brewSh runs a shell line with $brew set to Homebrew's path.
func (e machineEnv) brewSh(label, line, note string) Action {
	if e.brew == "" {
		return Action{Label: label, Note: "needs Homebrew first"}
	}
	return Action{Label: label, Argv: []string{"/bin/sh", "-c", "brew=" + shQuote(e.brew) + "; " + line}, Note: note}
}

func (e machineEnv) brewArgs(label string, args ...string) Action {
	if e.brew == "" {
		return Action{Label: label, Note: "needs Homebrew first"}
	}
	return Action{Label: label, Argv: append([]string{e.brew}, args...)}
}

func (e machineEnv) brewInstall() Action {
	return Action{Label: "install", Argv: []string{"/bin/bash", "-c", brewInstallScript}, Note: "the installer asks for your password here"}
}

func (e machineEnv) sbxInstall(reinstall bool) Action {
	switch {
	case e.goos == "darwin" && reinstall:
		return e.brewArgs("reinstall", "reinstall", "docker/tap/sbx")
	case e.goos == "darwin":
		return e.brewArgs("install", "install", "docker/tap/sbx")
	case e.ubuntu && e.apt:
		return Action{Label: "install", Argv: []string{"/bin/sh", "-c", sbxAptInstall}, Note: "uses sudo; sign out and in again for the kvm group"}
	}
	return Action{Label: "install", URL: sbxDocs}
}

// runtimeActions starts an installed runtime, or offers to install one:
// colima first, then Docker Desktop and Apple container.
func (e machineEnv) runtimeActions(installed []string) []Action {
	if e.goos != "darwin" {
		return []Action{{Label: "install Docker Engine", URL: engineDocs}}
	}
	var out []Action
	for _, rt := range installed {
		switch rt {
		case "colima":
			out = append(out, Action{Label: "colima", Argv: []string{"colima", "start"}})
		case "docker-desktop":
			out = append(out, Action{Label: "Docker Desktop", Argv: []string{"open", "-a", "Docker"}, Note: "check again once Docker Desktop says it is running"})
		case "container":
			out = append(out, Action{Label: "Apple container", Argv: []string{"container", "system", "start"}})
		}
	}
	if len(out) > 0 {
		return out
	}
	return []Action{
		e.brewSh("colima", `"$brew" install colima docker && colima start`, ""),
		e.brewSh("Docker Desktop", `"$brew" install --cask docker-desktop && open -a Docker`, "check again once Docker Desktop says it is running"),
		e.brewSh("Apple container", `"$brew" install container && container system start`, ""),
	}
}

// buildxInstall installs the docker-buildx formula and links it where the
// docker CLI looks for plugins, then shows `docker buildx version`.
func (e machineEnv) buildxInstall(withDocker bool) Action {
	if e.goos != "darwin" {
		return Action{Label: "install", URL: buildxDocs}
	}
	pkgs := "docker-buildx"
	if withDocker {
		pkgs = "docker docker-buildx"
	}
	return e.brewSh("install", `"$brew" install `+pkgs+` && mkdir -p "$HOME/.docker/cli-plugins" && ln -sfn "$("$brew" --prefix)/bin/docker-buildx" "$HOME/.docker/cli-plugins/docker-buildx" && docker buildx version`, "")
}

func (e machineEnv) pkgInstall(formula, aptPkg, docs string) Action {
	switch {
	case e.goos == "darwin":
		return e.brewArgs("install", "install", formula)
	case e.apt:
		return Action{Label: "install", Argv: []string{"sudo", "apt-get", "install", "-y", aptPkg}, Note: "uses sudo"}
	}
	return Action{Label: "install", URL: docs}
}

func (e machineEnv) ghInstall() Action {
	if e.goos != "darwin" {
		return Action{Label: "install", URL: ghLinuxDocs}
	}
	return e.brewSh("install and sign in", `"$brew" install gh && gh auth login`, "optional: for private repositories")
}

// pythonCheck needs python3 3.11 or newer for the engine.
func pythonCheck(ctx context.Context, o Options, e machineEnv) Result {
	fix := e.pkgInstall("python@3.13", "python3", pythonDocs)
	if !e.tool(o, "python3") {
		return with(res("python", "python3 (engine)", Fail, "not installed (3.11 or newer)", "brew install python@3.13"), fix)
	}
	v, err := o.Run(ctx, "python3", "-c", "import sys; print('%d.%d' % sys.version_info[:2])")
	if err != nil {
		return with(res("python", "python3 (engine)", Fail, "could not run python3", "brew install python@3.13"), fix)
	}
	v = strings.TrimSpace(v)
	maj, min, ok := strings.Cut(v, ".")
	a, err1 := strconv.Atoi(maj)
	b, err2 := strconv.Atoi(min)
	if !ok || err1 != nil || err2 != nil {
		return with(res("python", "python3 (engine)", Fail, "unknown version", "brew install python@3.13"), fix)
	}
	if a < 3 || (a == 3 && b < 11) {
		return with(res("python", "python3 (engine)", Fail, v+" (3.11 or newer needed)", "brew install python@3.13"), fix)
	}
	return res("python", "python3 (engine)", OK, v, "")
}
