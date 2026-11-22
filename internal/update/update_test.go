package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		tag, cur string
		want     bool
	}{{"v0.5.0", "v0.4.9", true}, {"v0.4.0", "v0.4.0", false}, {"v1.0.0", "v0.9.9", true}, {"v0.3.0", "v0.4.0", false}, {"v9.9.9", "dev", false}}
	for _, c := range cases {
		if got := Newer(c.tag, c.cur); got != c.want {
			t.Fatalf("Newer(%s,%s)=%v", c.tag, c.cur, got)
		}
	}
}

func TestVerifySumDetectsTampering(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "burner_1.0.0_darwin_arm64.tar.gz")
	os.WriteFile(f, []byte("good"), 0o644)
	sum := sha256.Sum256([]byte("good"))
	sums := filepath.Join(d, "checksums.txt")
	os.WriteFile(sums, []byte(hex.EncodeToString(sum[:])+"  burner_1.0.0_darwin_arm64.tar.gz\n"), 0o644)
	if err := VerifySum(f, sums); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(f, []byte("evil"), 0o644)
	if err := VerifySum(f, sums); err == nil {
		t.Fatal("tampered archive accepted")
	}
}

func TestCatalogURLRules(t *testing.T) {
	for _, bad := range []string{"-uhack", "ext::sh -c id", "file:///etc", "https://user:tok@github.com/a/b", "http://x/y"} {
		if validateURL(bad) == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	for _, ok := range []string{"https://github.com/acme/recipes.git", "git@github.com:acme/recipes.git"} {
		if err := validateURL(ok); err != nil {
			t.Fatalf("refused %q: %v", ok, err)
		}
	}
}

func TestPullReportsAddedAndUpdated(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git missing")
	}
	ctx := context.Background()
	up := t.TempDir()
	git := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %s", args, out)
		}
	}
	write := func(rel, body string) {
		p := filepath.Join(up, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(body), 0o644)
	}
	git(up, "init", "-q", "-b", "main")
	write("recipes/devsecops/a/RECIPE.md", "a")
	git(up, "add", "-A")
	git(up, "commit", "-qm", "a")
	clone := filepath.Join(t.TempDir(), "catalog")
	git("", "clone", "-q", up, clone)

	write("recipes/devsecops/a/recipe.yaml", "x")
	write("recipes/pentest/b/RECIPE.md", "b")
	git(up, "add", "-A")
	git(up, "commit", "-qm", "b")

	c, err := Pull(ctx, clone)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Added) != 1 || c.Added[0] != "pentest/b" || len(c.Updated) != 1 || c.Updated[0] != "devsecops/a" {
		t.Fatalf("change = %+v", c)
	}
}

func release(t *testing.T, srv string, names ...string) Release {
	r := Release{Tag: "v1.0.0"}
	for _, n := range names {
		r.Assets = append(r.Assets, struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		}{n, srv + "/" + n})
	}
	return r
}

func serveRelease(t *testing.T, archive []byte, sums string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch filepath.Base(r.URL.Path) {
		case AssetName("v1.0.0"):
			w.Write(archive)
		case "checksums.txt":
			w.Write([]byte(sums))
		default:
			w.Write([]byte("sig"))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func tarball(t *testing.T, body string) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "burner", Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
	tw.Write([]byte(body))
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestUnsignedReleaseIsRefused(t *testing.T) {
	arc := tarball(t, "new")
	sum := sha256.Sum256(arc)
	srv := serveRelease(t, arc, hex.EncodeToString(sum[:])+"  "+AssetName("v1.0.0")+"\n")
	_, err := Download(context.Background(), release(t, srv.URL, AssetName("v1.0.0"), "checksums.txt"), t.TempDir())
	if err == nil {
		t.Fatal("release without signature accepted")
	}
}

func TestBadSignatureStopsBeforeChecksum(t *testing.T) {
	arc := tarball(t, "new")
	sum := sha256.Sum256(arc)
	srv := serveRelease(t, arc, hex.EncodeToString(sum[:])+"  "+AssetName("v1.0.0")+"\n")
	old := VerifySignature
	defer func() { VerifySignature = old }()
	VerifySignature = func(context.Context, string, string, string) error { return errors.New("bad signature") }
	_, err := Download(context.Background(), release(t, srv.URL, AssetName("v1.0.0"), "checksums.txt", "checksums.txt.sig", "checksums.txt.pem"), t.TempDir())
	if err == nil || err.Error() != "bad signature" {
		t.Fatalf("err = %v", err)
	}
}

func TestWrongChecksumLeavesBinaryUntouched(t *testing.T) {
	arc := tarball(t, "new")
	srv := serveRelease(t, arc, strings.Repeat("0", 64)+"  "+AssetName("v1.0.0")+"\n")
	old := VerifySignature
	defer func() { VerifySignature = old }()
	VerifySignature = func(context.Context, string, string, string) error { return nil }
	if _, err := Download(context.Background(), release(t, srv.URL, AssetName("v1.0.0"), "checksums.txt", "checksums.txt.sig", "checksums.txt.pem"), t.TempDir()); err == nil {
		t.Fatal("wrong checksum accepted")
	}
}

func TestInstallReplacesAtomically(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "burner")
	os.WriteFile(exe, []byte("old"), 0o755)
	arc := filepath.Join(dir, "a.tar.gz")
	os.WriteFile(arc, tarball(t, "new"), 0o644)
	if err := Install(arc, exe); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "new" {
		t.Fatalf("binary = %q", b)
	}
	os.WriteFile(arc, []byte("not a tarball"), 0o644)
	if err := Install(arc, exe); err == nil {
		t.Fatal("garbage archive installed")
	}
	if b, _ := os.ReadFile(exe); string(b) != "new" {
		t.Fatal("failed install touched the binary")
	}
}
