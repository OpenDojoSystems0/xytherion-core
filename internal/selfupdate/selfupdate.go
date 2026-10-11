// Package selfupdate lets the agent replace itself with a newer official
// release.
//
// Trust model: every release is signed with the Xytherion ed25519 key. The
// public half is compiled into the agent (pubkey.go); the private half never
// leaves the maintainers' machine and CI secrets. An update is applied only if
//  1. the signature over the release's checksums (or the self-hosted
//     manifest) verifies against that key, and
//  2. the downloaded binary matches the signed SHA-256.
//
// A compromised GitHub account, mirror or update server therefore cannot push
// a malicious binary: it cannot produce a valid signature.
package selfupdate

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xytherion/core/pkg/safenet"
)

// DefaultRepo is where official releases are published.
const DefaultRepo = "OpenDojoSystems0/xytherion-core"

var (
	// ErrDisabled is returned for development builds (version "dev").
	ErrDisabled = errors.New("mises à jour désactivées pour une version de développement")
	// ErrNoKey is returned when the build carries no update signing key.
	ErrNoKey = errors.New("aucune clé de signature des mises à jour dans ce binaire")
	// ErrBadSignature is returned when a release is unsigned or tampered with.
	ErrBadSignature = errors.New("signature de la mise à jour absente ou invalide — mise à jour refusée")
)

var tagRe = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// Release is a verified, newer version ready to be applied.
type Release struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
}

// Manifest is the self-hosted format used with XYTHERION_UPDATE_URL.
type Manifest struct {
	Version   string `json:"version"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature"` // base64 ed25519 over ManifestMessage(...)
}

// ManifestMessage is the exact byte string signed for a self-hosted manifest.
func ManifestMessage(version, url, sha string) []byte {
	return []byte("xytherion-update\n" + version + "\n" + url + "\n" + strings.ToLower(sha) + "\n")
}

type Updater struct {
	CurrentVersion string
	ManifestURL    string // self-hosted manifest; empty = GitHub releases
	Repo           string

	apiBase, dlBase string // overridable in tests
	pubKey          ed25519.PublicKey
	goos, goarch    string
	client          *http.Client
}

func New(manifestURL, currentVersion string) *Updater {
	u := &Updater{
		CurrentVersion: currentVersion,
		ManifestURL:    manifestURL,
		Repo:           DefaultRepo,
		apiBase:        "https://api.github.com",
		dlBase:         "https://github.com",
		goos:           runtime.GOOS,
		goarch:         runtime.GOARCH,
		client: &http.Client{
			Timeout:   2 * time.Minute,
			Transport: safenet.Transport(),
			// GitHub downloads redirect to its CDN: follow, but only over HTTPS.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("too many redirects")
				}
				return requireHTTPS(req.URL.String())
			},
		},
	}
	if key, err := base64.StdEncoding.DecodeString(PublicKey); err == nil && len(key) == ed25519.PublicKeySize {
		u.pubKey = ed25519.PublicKey(key)
	}
	return u
}

// Enabled reports why updates are unavailable, or nil when they can run.
func (u *Updater) Enabled() error {
	if u.CurrentVersion == "" || u.CurrentVersion == "dev" {
		return ErrDisabled
	}
	if len(u.pubKey) != ed25519.PublicKeySize {
		return ErrNoKey
	}
	return nil
}

// requireHTTPS refuses plain-HTTP update sources.
func requireHTTPS(raw string) error {
	if !strings.HasPrefix(strings.ToLower(raw), "https://") {
		return fmt.Errorf("selfupdate: refusing non-HTTPS URL %q", raw)
	}
	return nil
}

func (u *Updater) get(url string, limit int64) ([]byte, error) {
	if err := requireHTTPS(url); err != nil {
		return nil, err
	}
	resp, err := u.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("selfupdate: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("selfupdate: %s returned %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// Check returns a verified newer release, or nil when up to date.
func (u *Updater) Check() (*Release, error) {
	if err := u.Enabled(); err != nil {
		return nil, err
	}
	var (
		rel *Release
		err error
	)
	if u.ManifestURL != "" {
		rel, err = u.fromManifest()
	} else {
		rel, err = u.fromGitHub()
	}
	if err != nil {
		return nil, err
	}
	if !isNewer(rel.Version, u.CurrentVersion) {
		return nil, nil
	}
	return rel, nil
}

// fromGitHub reads the latest release, verifies the signature of its
// checksums.txt and picks the asset for this OS/arch.
func (u *Updater) fromGitHub() (*Release, error) {
	body, err := u.get(u.apiBase+"/repos/"+u.Repo+"/releases/latest", 1<<20)
	if err != nil {
		return nil, err
	}
	var latest struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &latest); err != nil {
		return nil, fmt.Errorf("selfupdate: decode release: %w", err)
	}
	if !tagRe.MatchString(latest.TagName) {
		return nil, fmt.Errorf("selfupdate: unexpected release tag %q", latest.TagName)
	}

	base := u.dlBase + "/" + u.Repo + "/releases/download/" + latest.TagName + "/"
	sums, err := u.get(base+"checksums.txt", 64<<10)
	if err != nil {
		return nil, err
	}
	sigText, err := u.get(base+"checksums.txt.sig", 4<<10)
	if err != nil {
		return nil, ErrBadSignature
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigText)))
	if err != nil || !ed25519.Verify(u.pubKey, sums, sig) {
		return nil, ErrBadSignature
	}

	asset := "xytherion-" + u.goos + "-" + u.goarch
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == asset && len(f[0]) == 64 {
			return &Release{Version: latest.TagName, URL: base + asset, SHA256: strings.ToLower(f[0])}, nil
		}
	}
	return nil, fmt.Errorf("selfupdate: no %s binary in release %s", asset, latest.TagName)
}

// fromManifest reads and verifies a self-hosted, signed manifest.
func (u *Updater) fromManifest() (*Release, error) {
	body, err := u.get(u.ManifestURL, 64<<10)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("selfupdate: decode manifest: %w", err)
	}
	if !tagRe.MatchString(m.Version) || len(m.SHA256) != 64 {
		return nil, fmt.Errorf("selfupdate: invalid manifest")
	}
	if err := requireHTTPS(m.URL); err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil || !ed25519.Verify(u.pubKey, ManifestMessage(m.Version, m.URL, m.SHA256), sig) {
		return nil, ErrBadSignature
	}
	return &Release{Version: m.Version, URL: m.URL, SHA256: strings.ToLower(m.SHA256)}, nil
}

// ManagedBy names the package manager owning exe ("homebrew"), or "".
// Such installs must be upgraded through that package manager.
func ManagedBy(exe string) string {
	for _, marker := range []string{"/Cellar/", "/homebrew/", "/linuxbrew/"} {
		if strings.Contains(exe, marker) {
			return "homebrew"
		}
	}
	return ""
}

// Executable returns the real path of the running binary.
func Executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// ApplyTo downloads rel, verifies its SHA-256 and atomically replaces target.
func (u *Updater) ApplyTo(rel *Release, target string) error {
	if ManagedBy(target) != "" {
		return errors.New("installé via Homebrew : mettez à jour avec « brew upgrade xytherion »")
	}
	if err := requireHTTPS(rel.URL); err != nil {
		return err
	}
	if len(rel.SHA256) != 64 {
		return errors.New("selfupdate: invalid checksum")
	}

	// Same directory as the binary so the final rename is atomic.
	tmp, err := os.CreateTemp(filepath.Dir(target), ".xytherion-update-*")
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("droits insuffisants pour remplacer %s — relancez le script d'installation, ou faites tourner l'agent en service", target)
		}
		return fmt.Errorf("selfupdate: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed

	resp, err := u.client.Get(rel.URL)
	if err != nil {
		tmp.Close()
		return fmt.Errorf("selfupdate: download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		tmp.Close()
		return fmt.Errorf("selfupdate: download returned %d", resp.StatusCode)
	}

	h := sha256.New()
	// An agent binary is ~10 MB; cap downloads at 200 MB.
	if _, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, 200<<20)); err != nil {
		tmp.Close()
		return fmt.Errorf("selfupdate: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("selfupdate: close temp: %w", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != rel.SHA256 {
		return fmt.Errorf("selfupdate: checksum mismatch (got %s, want %s)", got, rel.SHA256)
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return fmt.Errorf("selfupdate: chmod: %w", err)
	}
	if err := os.Rename(tmpName, target); err != nil {
		return fmt.Errorf("selfupdate: replace binary: %w", err)
	}
	return nil
}

// Apply replaces the running binary and re-executes it in place (same PID,
// so systemd and launchd keep supervising it). It only returns on error.
func (u *Updater) Apply(rel *Release) error {
	exe, err := Executable()
	if err != nil {
		return fmt.Errorf("selfupdate: resolve executable: %w", err)
	}
	if err := u.ApplyTo(rel, exe); err != nil {
		return err
	}
	log.Printf("[selfupdate] updated to %s, restarting…", rel.Version)
	return syscall.Exec(exe, os.Args, os.Environ())
}

func isNewer(candidate, current string) bool {
	return compareSemver(candidate, current) > 0
}

func compareSemver(a, b string) int {
	ap, bp := parseSemver(a), parseSemver(b)
	for i := range ap {
		if ap[i] > bp[i] {
			return 1
		}
		if ap[i] < bp[i] {
			return -1
		}
	}
	return 0
}

func parseSemver(v string) [3]int {
	v = strings.TrimPrefix(v, "v")
	// Drop pre-release/build suffixes; guard against inputs like "" or "-rc1"
	// where FieldsFunc returns no fields.
	fields := strings.FieldsFunc(v, func(r rune) bool { return r == '-' || r == '+' })
	if len(fields) == 0 {
		return [3]int{}
	}
	parts := strings.SplitN(fields[0], ".", 3)
	var out [3]int
	for i, p := range parts {
		out[i], _ = strconv.Atoi(p)
	}
	return out
}
