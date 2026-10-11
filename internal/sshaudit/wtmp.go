package sshaudit

import (
	"encoding/binary"
	"os"
	"strings"
	"time"

	"github.com/xytherion/core/pkg/metrics"
)

// Fallback for systems without the `last` command (minimal Debian 13+, Alpine,
// containers): read glibc's binary utmp records from /var/log/wtmp directly.
const (
	utmpSize    = 384
	userProcess = 7
)

func wtmpLogins(path string, n int) []metrics.SSHLogin {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parseWtmp(data, n)
}

// parseWtmp returns the n newest remote logins, newest first.
func parseWtmp(data []byte, n int) []metrics.SSHLogin {
	var out []metrics.SSHLogin
	for end := len(data) - len(data)%utmpSize; end >= utmpSize && len(out) < n; end -= utmpSize {
		rec := data[end-utmpSize : end]
		if binary.LittleEndian.Uint16(rec[0:2]) != userProcess {
			continue
		}
		host := cstr(rec[76:332])
		if host == "" { // local console login, not SSH
			continue
		}
		out = append(out, metrics.SSHLogin{
			User:    cstr(rec[44:76]),
			From:    host,
			Time:    time.Unix(int64(int32(binary.LittleEndian.Uint32(rec[340:344]))), 0),
			Success: true,
			TTY:     cstr(rec[8:40]),
		})
	}
	return out
}

func cstr(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
