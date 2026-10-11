// Package sysexec runs system tools (ufw, nft, last, pfctl…) safely.
//
// The agent often runs as root: resolving tools through $PATH would let a
// tampered PATH substitute any binary. Tools are therefore looked up only in
// the standard system directories, and run with a fixed environment. LC_ALL=C
// also guarantees English output, which the parsers rely on (a French
// system prints "État : actif" instead of "Status: active").
package sysexec

import (
	"os"
	"os/exec"
	"path/filepath"
)

var systemDirs = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// Lookup returns the absolute path of a system tool, or "" if absent.
func Lookup(name string) string {
	if filepath.IsAbs(name) {
		if fi, err := os.Stat(name); err == nil && !fi.IsDir() {
			return name
		}
		return ""
	}
	for _, dir := range systemDirs {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
}

// Command builds an *exec.Cmd for a system tool. When the tool is missing,
// the returned command fails on Run/Output like a missing binary would.
func Command(name string, args ...string) *exec.Cmd {
	path := Lookup(name)
	if path == "" {
		path = "/nonexistent/" + filepath.Base(name)
	}
	cmd := exec.Command(path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C"}
	return cmd
}
