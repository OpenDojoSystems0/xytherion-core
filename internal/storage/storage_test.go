package storage

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSaveLoadRoundTripIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "data.json")
	s := New(path)

	in := Data{
		Monitors: []string{"https://example.com"},
		Webhooks: []RawHook{{ID: "1", Name: "ops", URL: "https://hooks.example.com/secret", Type: "slack", Enabled: true}},
	}
	if err := s.Save(in); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("data file mode = %v, want 0600 (webhook URLs are secrets)", info.Mode().Perm())
	}

	out, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(out.Monitors) != 1 || len(out.Webhooks) != 1 || out.Webhooks[0].URL != in.Webhooks[0].URL {
		t.Fatalf("round trip mismatch: %+v", out)
	}
}

func TestLoadMissingFileIsEmpty(t *testing.T) {
	dir := t.TempDir()
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	os.Chdir(dir) // no legacy .xytherion.json here

	d, err := New(filepath.Join(dir, "absent.json")).Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(d.Monitors)+len(d.Webhooks) != 0 {
		t.Fatalf("expected empty data, got %+v", d)
	}
}

func TestDefaultPathIsAbsolute(t *testing.T) {
	if p := DefaultPath(); !filepath.IsAbs(p) {
		t.Fatalf("DefaultPath() = %q, want an absolute path independent of the working directory", p)
	}
}
