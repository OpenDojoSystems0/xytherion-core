package sshaudit

import (
	"bufio"
	"bytes"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/xytherion/core/internal/sysexec"
	"github.com/xytherion/core/pkg/metrics"
)

// LastLogins returns the n most recent SSH logins via the `last` command.
func LastLogins(n int) []metrics.SSHLogin {
	if n <= 0 {
		n = 20
	}
	flag := "-" + strconv.Itoa(n)
	switch runtime.GOOS {
	case "darwin":
		return parseLast(runCmd("last", flag), n)
	default:
		if out := runCmd("last", flag, "-w"); out != nil {
			return parseLast(out, n)
		}
		return wtmpLogins("/var/log/wtmp", n)
	}
}

func runCmd(name string, args ...string) []byte {
	out, err := sysexec.Command(name, args...).Output()
	if err != nil {
		return nil
	}
	return out
}

// parseLast parses output of the `last` command, capped at limit entries.
// Format (macOS/Linux): USER TTY FROM DATE TIME DURATION
func parseLast(data []byte, limit int) []metrics.SSHLogin {
	if data == nil {
		return nil
	}
	var logins []metrics.SSHLogin
	scanner := bufio.NewScanner(bytes.NewReader(data))
	year := time.Now().Year()

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "wtmp") || strings.HasPrefix(line, "reboot") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		user := fields[0]
		tty := fields[1]

		// Only SSH logins (pts/* on Linux, s* on macOS, or "from" field is an IP/hostname)
		from := ""
		if len(fields) >= 3 && tty != "console" {
			f := fields[2]
			if strings.Contains(f, ".") || strings.Contains(f, ":") {
				from = f
			}
		}

		// Parse date — `last` gives e.g. "Mon Jan  6 14:32"
		t := parseLastTime(fields, year)

		logins = append(logins, metrics.SSHLogin{
			User:    user,
			From:    from,
			Time:    t,
			Success: true,
			TTY:     tty,
		})

		if len(logins) >= limit {
			break
		}
	}
	return logins
}

var months = map[string]time.Month{
	"Jan": time.January, "Feb": time.February, "Mar": time.March,
	"Apr": time.April, "May": time.May, "Jun": time.June,
	"Jul": time.July, "Aug": time.August, "Sep": time.September,
	"Oct": time.October, "Nov": time.November, "Dec": time.December,
}

func parseLastTime(fields []string, year int) time.Time {
	// Try to find Mon Jan DD HH:MM pattern in fields
	for i := 2; i+3 < len(fields); i++ {
		mon, ok := months[fields[i]]
		if !ok {
			continue
		}
		day := 0
		for _, c := range fields[i+1] {
			if c >= '0' && c <= '9' {
				day = day*10 + int(c-'0')
			}
		}
		if day == 0 {
			continue
		}
		var h, m int
		parts := strings.Split(fields[i+2], ":")
		if len(parts) == 2 {
			for _, c := range parts[0] {
				if c >= '0' && c <= '9' {
					h = h*10 + int(c-'0')
				}
			}
			for _, c := range parts[1] {
				if c >= '0' && c <= '9' {
					m = m*10 + int(c-'0')
				}
			}
			return time.Date(year, mon, day, h, m, 0, 0, time.Local)
		}
	}
	return time.Time{}
}
