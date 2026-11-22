// Package update keeps recipe catalogs and the burner binary current.
//
// Catalogs are git checkouts under ~/.burner: the official one in catalog/,
// team catalogs in catalogs/<name>/. Updating fetches and fast-forwards
// only, so local edits are never overwritten; user recipes live elsewhere
// (~/.burner/recipes) and are never touched.
package update

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

// OfficialRepo is the catalog cloned on first use.
const OfficialRepo = "https://github.com/BRYANN2K/sbx-burner.git"

// Git runs git; tests replace it.
var Git = func(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

var safeName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// Change summarizes a catalog update.
type Change struct {
	Catalog string   `json:"catalog"`
	From    string   `json:"from"`
	To      string   `json:"to"`
	Added   []string `json:"added"`
	Updated []string `json:"updated"`
}

// Catalogs returns every catalog dir under home: official first.
func Catalogs(home string) []string {
	var out []string
	if isGit(filepath.Join(home, "catalog")) {
		out = append(out, filepath.Join(home, "catalog"))
	}
	entries, _ := os.ReadDir(filepath.Join(home, "catalogs"))
	for _, e := range entries {
		if p := filepath.Join(home, "catalogs", e.Name()); e.IsDir() && isGit(p) {
			out = append(out, p)
		}
	}
	return out
}

// AddCatalog clones a team catalog. Only https and ssh git URLs.
func AddCatalog(ctx context.Context, home, url, name string) (string, error) {
	if err := validateURL(url); err != nil {
		return "", err
	}
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(strings.TrimRight(url, "/")), ".git")
	}
	name = strings.ToLower(name)
	if !safeName.MatchString(name) {
		return "", fmt.Errorf("catalog name %q: lowercase letters, digits, dots and dashes", name)
	}
	dest := filepath.Join(home, "catalogs", name)
	if _, err := os.Stat(dest); err == nil {
		return "", fmt.Errorf("catalog %s already exists", name)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", err
	}
	if out, err := Git(ctx, "", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "-c", "protocol.ssh.allow=always",
		"clone", "--depth", "50", "--", url, dest); err != nil {
		return "", fmt.Errorf("clone: %s", out)
	}
	return dest, nil
}

// EnsureOfficial clones the official catalog when it is missing.
func EnsureOfficial(ctx context.Context, home string) (string, error) {
	dest := filepath.Join(home, "catalog")
	if isGit(dest) {
		return dest, nil
	}
	if err := os.MkdirAll(home, 0o755); err != nil {
		return "", err
	}
	if out, err := Git(ctx, "", "clone", "--depth", "50", "--", OfficialRepo, dest); err != nil {
		return "", fmt.Errorf("clone %s: %s", OfficialRepo, out)
	}
	return dest, nil
}

// Pull fast-forwards one catalog and reports which recipes changed.
func Pull(ctx context.Context, dir string) (Change, error) {
	c := Change{Catalog: filepath.Base(dir)}
	from, err := Git(ctx, dir, "rev-parse", "HEAD")
	if err != nil {
		return c, fmt.Errorf("%s: not a git checkout", dir)
	}
	if out, err := Git(ctx, dir, "pull", "--ff-only", "--quiet"); err != nil {
		return c, fmt.Errorf("%s: cannot fast-forward (local changes?): %s", c.Catalog, out)
	}
	to, _ := Git(ctx, dir, "rev-parse", "HEAD")
	c.From, c.To = short(from), short(to)
	if from == to {
		return c, nil
	}
	diff, _ := Git(ctx, dir, "diff", "--name-status", from, to, "--", "recipes")
	added, updated := map[string]bool{}, map[string]bool{}
	for _, line := range strings.Split(diff, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		parts := strings.Split(f[len(f)-1], "/")
		if len(parts) < 4 {
			continue
		}
		id := parts[1] + "/" + parts[2]
		if f[0] == "A" && parts[3] == "RECIPE.md" {
			added[id] = true
		} else {
			updated[id] = true
		}
	}
	for id := range added {
		c.Added = append(c.Added, id)
		delete(updated, id)
	}
	for id := range updated {
		c.Updated = append(c.Updated, id)
	}
	sort.Strings(c.Added)
	sort.Strings(c.Updated)
	return c, nil
}

// Release is the latest published burner release.
type Release struct {
	Tag     string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// HTTP is the client for release checks; tests replace it.
var HTTP = &http.Client{Timeout: 15 * time.Second}

// ReleasesAPI is the GitHub endpoint for the latest release.
var ReleasesAPI = "https://api.github.com/repos/BRYANN2K/sbx-burner/releases/latest"

// Latest asks GitHub for the newest release. BURNER_NO_UPDATE_CHECK=1 skips it.
func Latest(ctx context.Context) (Release, error) {
	var r Release
	if os.Getenv("BURNER_NO_UPDATE_CHECK") == "1" {
		return r, errors.New("update check disabled (BURNER_NO_UPDATE_CHECK=1)")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ReleasesAPI, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := HTTP.Do(req)
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return r, fmt.Errorf("release check: HTTP %d", resp.StatusCode)
	}
	return r, json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r)
}

// Newer reports whether tag is newer than current (semver vX.Y.Z).
func Newer(tag, current string) bool {
	parse := func(v string) [3]int {
		var a [3]int
		fmt.Sscanf(strings.TrimPrefix(v, "v"), "%d.%d.%d", &a[0], &a[1], &a[2])
		return a
	}
	if current == "dev" {
		return false
	}
	t, c := parse(tag), parse(current)
	for i := range t {
		if t[i] != c[i] {
			return t[i] > c[i]
		}
	}
	return false
}

// AssetName is the goreleaser archive name for this platform.
func AssetName(tag string) string {
	return fmt.Sprintf("burner_%s_%s_%s.tar.gz", strings.TrimPrefix(tag, "v"), runtime.GOOS, runtime.GOARCH)
}

// SignerIdentity pins who may sign releases: the release workflow of the
// official repository, on a version tag.
const SignerIdentity = `^https://github\.com/BRYANN2K/sbx-burner/\.github/workflows/release\.yml@refs/tags/v`

// VerifySignature checks checksums.txt against its keyless cosign
// signature. Tests replace it.
var VerifySignature = func(ctx context.Context, sums, sig, cert string) error {
	if _, err := exec.LookPath("cosign"); err != nil {
		return errors.New("cosign is required to verify a burner release (brew install cosign)")
	}
	out, err := exec.CommandContext(ctx, "cosign", "verify-blob",
		"--certificate", cert, "--signature", sig,
		"--certificate-identity-regexp", SignerIdentity,
		"--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", sums).CombinedOutput()
	if err != nil {
		return fmt.Errorf("signature check failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// Download fetches the archive, checksums.txt and its signature, verifies
// the signature FIRST (fail closed: no signature, no update), then the
// archive's sha256 against the now-trusted checksums.
func Download(ctx context.Context, r Release, dir string) (string, error) {
	want := AssetName(r.Tag)
	find := func(name string) string {
		for _, a := range r.Assets {
			if a.Name == name {
				return a.URL
			}
		}
		return ""
	}
	urls := map[string]string{
		want:                find(want),
		"checksums.txt":     find("checksums.txt"),
		"checksums.txt.sig": find("checksums.txt.sig"),
		"checksums.txt.pem": find("checksums.txt.pem"),
	}
	for name, u := range urls {
		if u == "" {
			return "", fmt.Errorf("release %s has no %s: refusing an unsigned update", r.Tag, name)
		}
	}
	for name, u := range urls {
		if err := fetch(ctx, u, filepath.Join(dir, name)); err != nil {
			return "", err
		}
	}
	sums := filepath.Join(dir, "checksums.txt")
	if err := VerifySignature(ctx, sums, sums+".sig", sums+".pem"); err != nil {
		return "", err
	}
	archive := filepath.Join(dir, want)
	if err := VerifySum(archive, sums); err != nil {
		return "", err
	}
	return archive, nil
}

// Install extracts the burner binary from a verified archive and replaces
// exe atomically: write a temp file next to it, chmod, rename. On any error
// the current binary is left untouched.
func Install(archive, exe string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return errors.New("archive has no burner binary")
		}
		if err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg || filepath.Base(h.Name) != "burner" {
			continue
		}
		tmp, err := os.CreateTemp(filepath.Dir(exe), ".burner-new-*")
		if err != nil {
			return err
		}
		if _, err := io.Copy(tmp, io.LimitReader(tr, 200<<20)); err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return err
		}
		tmp.Close()
		if err := os.Chmod(tmp.Name(), 0o755); err != nil {
			os.Remove(tmp.Name())
			return err
		}
		if err := os.Rename(tmp.Name(), exe); err != nil {
			os.Remove(tmp.Name())
			return err
		}
		return nil
	}
}

// VerifySum checks file's sha256 against a goreleaser checksums.txt.
func VerifySum(file, sums string) error {
	raw, err := os.ReadFile(sums)
	if err != nil {
		return err
	}
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[1] == filepath.Base(file) {
			if f[0] == got {
				return nil
			}
			return fmt.Errorf("checksum mismatch for %s", filepath.Base(file))
		}
	}
	return fmt.Errorf("%s not listed in checksums.txt", filepath.Base(file))
}

func fetch(ctx context.Context, url, dest string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", filepath.Base(dest), resp.StatusCode)
	}
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, io.LimitReader(resp.Body, 200<<20))
	return err
}

func validateURL(u string) error {
	if strings.HasPrefix(u, "-") || strings.Contains(u, "::") {
		return fmt.Errorf("refused catalog URL %q", u)
	}
	if strings.HasPrefix(u, "https://") {
		if strings.Contains(strings.SplitN(strings.TrimPrefix(u, "https://"), "/", 2)[0], "@") {
			return errors.New("catalog URL must not carry credentials; use your git login")
		}
		return nil
	}
	if strings.HasPrefix(u, "git@") || strings.HasPrefix(u, "ssh://") {
		return nil
	}
	return fmt.Errorf("catalog URL must be https or ssh: %q", u)
}

func isGit(dir string) bool {
	st, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil && st.IsDir()
}

func short(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}
