package sysexec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIgnoresUserPATH(t *testing.T) {
	// A fake "ls" first in PATH must never be picked.
	dir := t.TempDir()
	fake := filepath.Join(dir, "ls")
	os.WriteFile(fake, []byte("#!/bin/sh\necho hijacked\n"), 0o755)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	if p := Lookup("ls"); p == fake || !strings.HasPrefix(p, "/") {
		t.Fatalf("Lookup(ls) = %q, must come from a system directory", p)
	}
	out, err := Command("ls", "/").Output()
	if err != nil || strings.Contains(string(out), "hijacked") {
		t.Fatalf("Command used the hijacked binary: %q, %v", out, err)
	}
}

func TestForcesEnglishOutput(t *testing.T) {
	cmd := Command("env")
	out, err := cmd.Output()
	if err != nil {
		t.Skip("env not available")
	}
	if !strings.Contains(string(out), "LC_ALL=C") {
		t.Fatalf("LC_ALL=C missing from the tool environment: %s", out)
	}
}

func TestMissingToolFails(t *testing.T) {
	if _, err := Command("definitely-not-a-real-tool-xyz").Output(); err == nil {
		t.Fatal("missing tool did not fail")
	}
}
