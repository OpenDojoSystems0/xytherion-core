package selfupdate

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestIsNewer(t *testing.T) {
	cases := []struct {
		candidate, current string
		want               bool
	}{
		{"v0.3.0", "v0.2.9", true},
		{"v1.0.0", "v0.99.99", true},
		{"v0.2.0", "v0.2.0", false},
		{"v0.1.9", "v0.2.0", false},
		{"v0.3.0-rc1", "v0.2.0", true},
		// Malformed inputs must not panic.
		{"", "v0.1.0", false},
		{"-rc1", "v0.1.0", false},
		{"v0.1.0", "", true},
	}
	for _, c := range cases {
		if got := isNewer(c.candidate, c.current); got != c.want {
			t.Errorf("isNewer(%q, %q) = %v, want %v", c.candidate, c.current, got, c.want)
		}
	}
}

func TestEmbeddedKeyIsValid(t *testing.T) {
	if err := New("", "v0.1.0").Enabled(); err != nil {
		t.Fatalf("official build must carry a valid signing key: %v", err)
	}
}

func TestDevBuildsNeverUpdate(t *testing.T) {
	if _, err := New("", "dev").Check(); !errors.Is(err, ErrDisabled) {
		t.Fatalf("dev build Check() err = %v, want ErrDisabled", err)
	}
}

func TestRequireHTTPS(t *testing.T) {
	for _, bad := range []string{"http://x/y", "ftp://x/y", "file:///etc/passwd", ""} {
		if requireHTTPS(bad) == nil {
			t.Errorf("requireHTTPS(%q) = nil, want error", bad)
		}
	}
	if requireHTTPS("https://example.com/agent") != nil {
		t.Error("requireHTTPS rejected an https URL")
	}
}

/* ── End-to-end against a fake GitHub ─────────────────────────────── */

type fakeGitHub struct {
	srv       *httptest.Server
	priv      ed25519.PrivateKey
	tag       string
	binary    []byte
	sums      string
	sig       string // base64 signature over sums
	tamperBin bool
}

func newFakeGitHub(t *testing.T, tag string) *fakeGitHub {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := &fakeGitHub{priv: priv, tag: tag, binary: []byte("#!/bin/sh\necho xytherion " + tag + "\n")}
	asset := "xytherion-" + runtime.GOOS + "-" + runtime.GOARCH
	sum := sha256.Sum256(f.binary)
	f.sums = hex.EncodeToString(sum[:]) + "  " + asset + "\n" + strings.Repeat("0", 64) + "  xytherion-other-arch\n"
	f.sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(f.sums)))

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/acme/agent/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"tag_name": f.tag})
	})
	dl := "/acme/agent/releases/download/" + tag + "/"
	mux.HandleFunc(dl+"checksums.txt", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(f.sums)) })
	mux.HandleFunc(dl+"checksums.txt.sig", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(f.sig + "\n")) })
	mux.HandleFunc(dl+asset, func(w http.ResponseWriter, r *http.Request) {
		if f.tamperBin {
			w.Write([]byte("malware"))
			return
		}
		w.Write(f.binary)
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// updater wired to the fake server, trusting the fake's key.
func (f *fakeGitHub) updater(current string) *Updater {
	u := New("", current)
	u.Repo = "acme/agent"
	u.apiBase, u.dlBase = f.srv.URL, f.srv.URL
	u.client = f.srv.Client() // the real client blocks 127.0.0.1 (SSRF guard)
	u.pubKey = f.priv.Public().(ed25519.PublicKey)
	return u
}

func TestGitHubUpdateEndToEnd(t *testing.T) {
	f := newFakeGitHub(t, "v0.4.0")
	u := f.updater("v0.3.0")

	rel, err := u.Check()
	if err != nil || rel == nil {
		t.Fatalf("Check() = %v, %v; want a release", rel, err)
	}
	if rel.Version != "v0.4.0" {
		t.Fatalf("version = %s", rel.Version)
	}

	target := filepath.Join(t.TempDir(), "xytherion")
	os.WriteFile(target, []byte("old"), 0o755)
	if err := u.ApplyTo(rel, target); err != nil {
		t.Fatalf("ApplyTo: %v", err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != string(f.binary) {
		t.Fatalf("binary not replaced: %q", got)
	}
	if info, _ := os.Stat(target); info.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %v, want 0755", info.Mode().Perm())
	}
}

func TestUpToDateReturnsNil(t *testing.T) {
	f := newFakeGitHub(t, "v0.4.0")
	if rel, err := f.updater("v0.4.0").Check(); err != nil || rel != nil {
		t.Fatalf("Check() = %v, %v; want nil, nil", rel, err)
	}
}

func TestRejectsForgedSignature(t *testing.T) {
	f := newFakeGitHub(t, "v0.4.0")
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	f.sig = base64.StdEncoding.EncodeToString(ed25519.Sign(otherKey, []byte(f.sums)))
	if _, err := f.updater("v0.3.0").Check(); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("forged signature err = %v, want ErrBadSignature", err)
	}
}

func TestRejectsTamperedChecksums(t *testing.T) {
	f := newFakeGitHub(t, "v0.4.0")
	f.sums = strings.Replace(f.sums, f.sums[:8], "deadbeef", 1) // signature no longer matches
	if _, err := f.updater("v0.3.0").Check(); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered checksums err = %v, want ErrBadSignature", err)
	}
}

func TestRejectsTamperedBinary(t *testing.T) {
	f := newFakeGitHub(t, "v0.4.0")
	u := f.updater("v0.3.0")
	rel, err := u.Check()
	if err != nil {
		t.Fatal(err)
	}
	f.tamperBin = true
	target := filepath.Join(t.TempDir(), "xytherion")
	os.WriteFile(target, []byte("old"), 0o755)
	if err := u.ApplyTo(rel, target); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("tampered binary err = %v, want checksum mismatch", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "old" {
		t.Fatal("binary was replaced despite a checksum mismatch")
	}
}

func TestSignedManifest(t *testing.T) {
	f := newFakeGitHub(t, "v0.4.0")
	binURL := f.srv.URL + "/acme/agent/releases/download/v0.4.0/xytherion-" + runtime.GOOS + "-" + runtime.GOARCH
	sum := sha256.Sum256(f.binary)
	sha := hex.EncodeToString(sum[:])

	manifest := func(sig string) *httptest.Server {
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(Manifest{Version: "v0.4.0", URL: binURL, SHA256: sha, Signature: sig})
		}))
		t.Cleanup(s.Close)
		return s
	}

	good := base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv, ManifestMessage("v0.4.0", binURL, sha)))
	ms := manifest(good)
	u := f.updater("v0.3.0")
	u.ManifestURL = ms.URL
	if rel, err := u.Check(); err != nil || rel == nil || rel.SHA256 != sha {
		t.Fatalf("signed manifest Check() = %v, %v", rel, err)
	}

	bad := manifest(base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)))
	u.ManifestURL = bad.URL
	if _, err := u.Check(); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("unsigned manifest err = %v, want ErrBadSignature", err)
	}
}

func TestHomebrewInstallsAreLeftToBrew(t *testing.T) {
	u := New("", "v0.3.0")
	err := u.ApplyTo(&Release{URL: "https://example.com/x", SHA256: strings.Repeat("a", 64)}, "/opt/homebrew/Cellar/xytherion/0.3.0/bin/xytherion")
	if err == nil || !strings.Contains(err.Error(), "brew upgrade") {
		t.Fatalf("Homebrew path err = %v, want a brew upgrade hint", err)
	}
}

func TestReadOnlyDirectoryGivesClearError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "xytherion")
	os.WriteFile(target, []byte("old"), 0o755)
	os.Chmod(dir, 0o555)
	defer os.Chmod(dir, 0o755)
	u := New("", "v0.3.0")
	err := u.ApplyTo(&Release{URL: "https://example.com/x", SHA256: strings.Repeat("a", 64)}, target)
	if err == nil || !strings.Contains(err.Error(), "droits insuffisants") {
		t.Fatalf("read-only dir err = %v, want a permissions message", err)
	}
}
