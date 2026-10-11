package firewall

import (
	"runtime"
	"strconv"
	"strings"

	"github.com/xytherion/core/internal/sysexec"
	"github.com/xytherion/core/pkg/metrics"
)

// Status returns the current firewall status.
// macOS: pf (needs root) then the Application Firewall (works unprivileged).
// Linux: ufw, firewalld, nftables, then iptables — first engine found wins.
func Status() metrics.FirewallStatus {
	switch runtime.GOOS {
	case "darwin":
		if s := pfStatus(); s.Enabled {
			return s
		}
		if s := appFirewallStatus(); s.Engine != "" {
			return s
		}
		return pfStatus()
	default:
		for _, probe := range []func() metrics.FirewallStatus{ufwStatus, firewalldStatus, nftStatus} {
			if s := probe(); s.Engine != "" {
				return s
			}
		}
		return iptablesStatus()
	}
}

func pfStatus() metrics.FirewallStatus {
	out, err := sysexec.Command("pfctl", "-s", "info").Output()
	if err != nil {
		return metrics.FirewallStatus{Engine: "pf", Details: "pfctl nécessite les droits root"}
	}
	text := string(out)
	enabled := strings.Contains(text, "Status: Enabled")

	rules := 0
	rulesOut, _ := sysexec.Command("pfctl", "-s", "rules").Output()
	if rulesOut != nil {
		rules = countLines(string(rulesOut))
	}

	return metrics.FirewallStatus{
		Enabled: enabled,
		Engine:  "pf",
		Rules:   rules,
		Details: firstLine(text),
	}
}

// appFirewallStatus reads the macOS Application Firewall (System Settings →
// Network → Firewall). socketfilterfw answers without root.
func appFirewallStatus() metrics.FirewallStatus {
	const bin = "/usr/libexec/ApplicationFirewall/socketfilterfw"
	out, err := sysexec.Command(bin, "--getglobalstate").Output()
	if err != nil {
		return metrics.FirewallStatus{}
	}
	text := strings.ToLower(string(out))
	enabled := strings.Contains(text, "enabled") || strings.Contains(text, "state = 1") || strings.Contains(text, "state = 2")
	// "Total number of apps = 16" — the per-app allow/block rules.
	apps := 0
	if list, err := sysexec.Command(bin, "--listapps").Output(); err == nil {
		for _, line := range strings.Split(string(list), "\n") {
			if i := strings.Index(line, "Total number of apps ="); i >= 0 {
				apps, _ = strconv.Atoi(strings.TrimSpace(line[i+len("Total number of apps ="):]))
				break
			}
		}
	}
	details := "Pare-feu applicatif macOS désactivé"
	if enabled {
		details = "Pare-feu applicatif macOS actif"
	}
	return metrics.FirewallStatus{Enabled: enabled, Engine: "macOS", Rules: apps, Details: details}
}

func ufwStatus() metrics.FirewallStatus {
	out, err := sysexec.Command("ufw", "status", "verbose").Output()
	if err != nil {
		return metrics.FirewallStatus{}
	}
	text := string(out)
	enabled := strings.Contains(text, "Status: active")
	rules := countUFWRules(text)
	return metrics.FirewallStatus{
		Enabled: enabled,
		Engine:  "ufw",
		Rules:   rules,
		Details: firstLine(text),
	}
}

// countUFWRules counts the rows of the table `ufw status` prints after its
// "--" separator line (e.g. "22/tcp   ALLOW IN   Anywhere").
func countUFWRules(text string) int {
	rules, inTable := 0, false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "--"):
			inTable = true
		case inTable && line != "":
			rules++
		}
	}
	return rules
}

// firewalldStatus covers Fedora, RHEL, Rocky, Alma and CentOS Stream.
func firewalldStatus() metrics.FirewallStatus {
	out, err := sysexec.Command("firewall-cmd", "--state").CombinedOutput()
	if err != nil && len(out) == 0 {
		return metrics.FirewallStatus{}
	}
	state := strings.TrimSpace(string(out))
	if state != "running" && state != "not running" {
		return metrics.FirewallStatus{}
	}
	enabled := state == "running"
	rules := 0
	if enabled {
		if list, err := sysexec.Command("firewall-cmd", "--list-all").Output(); err == nil {
			for _, line := range strings.Split(string(list), "\n") {
				line = strings.TrimSpace(line)
				for _, key := range []string{"services:", "ports:", "rich rules:"} {
					if strings.HasPrefix(line, key) {
						rules += len(strings.Fields(strings.TrimPrefix(line, key)))
					}
				}
			}
		}
	}
	return metrics.FirewallStatus{Enabled: enabled, Engine: "firewalld", Rules: rules, Details: "firewalld " + state}
}

// nftStatus covers Debian 11+, Ubuntu 22.04+ and other nftables-native systems.
func nftStatus() metrics.FirewallStatus {
	out, err := sysexec.Command("nft", "list", "ruleset").Output()
	if err != nil {
		return metrics.FirewallStatus{}
	}
	text := string(out)
	rules := 0
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "table") || strings.HasPrefix(line, "chain") ||
			strings.HasPrefix(line, "type ") || line == "}" || strings.HasPrefix(line, "#") {
			continue
		}
		rules++
	}
	if strings.TrimSpace(text) == "" {
		return metrics.FirewallStatus{}
	}
	return metrics.FirewallStatus{Enabled: rules > 0, Engine: "nftables", Rules: rules, Details: strconv.Itoa(rules) + " règles nftables"}
}

func iptablesStatus() metrics.FirewallStatus {
	out, err := sysexec.Command("iptables", "-L", "--line-numbers", "-n").Output()
	if err != nil {
		return metrics.FirewallStatus{Engine: "iptables", Enabled: false, Details: "Aucun pare-feu détecté (ou droits root requis)"}
	}
	rules := countLines(string(out))
	enabled := rules > 3
	return metrics.FirewallStatus{
		Enabled: enabled,
		Engine:  "iptables",
		Rules:   rules,
		Details: strconv.Itoa(rules) + " règles",
	}
}

func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return s
}

func countLines(s string) int {
	n := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}
