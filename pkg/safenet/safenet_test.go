package safenet

import (
	"net"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	cases := []struct {
		ip      string
		private bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.254", true},
		{"::1", true},
		{"169.254.1.1", true}, // link-local
		{"fe80::1", true},     // IPv6 link-local
		{"10.0.0.1", true},    // RFC-1918
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.255.255", true},
		{"100.64.0.1", true},            // CGNAT
		{"fc00::1", true},               // IPv6 ULA
		{"fd00::1", true},               // IPv6 ULA
		{"1.1.1.1", false},              // Cloudflare DNS — public
		{"8.8.8.8", false},              // Google DNS — public
		{"2606:4700:4700::1111", false}, // Cloudflare IPv6 — public
		{"172.15.255.255", false},       // just outside RFC-1918
		{"172.32.0.0", false},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("invalid test IP: %s", c.ip)
		}
		got := IsPrivateIP(ip)
		if got != c.private {
			t.Errorf("IsPrivateIP(%s) = %v, want %v", c.ip, got, c.private)
		}
	}
}

func TestIsPrivateURL(t *testing.T) {
	cases := []struct {
		raw     string
		private bool
	}{
		{"http://localhost/foo", true},
		{"http://127.0.0.1:8080/api", true},
		{"http://10.0.0.1/", true},
		{"http://192.168.1.1/", true},
		{"http://[::1]/", true},
		{"https://1.1.1.1/", false},
		{"https://8.8.8.8/", false},
		{"not-a-url", true}, // no host → LookupHost("") fails → blocked (caller validates scheme first)
		{"http://", true},   // no host → blocked (validateHTTPURL would catch this before us)
	}
	for _, c := range cases {
		got := IsPrivateURL(c.raw)
		if got != c.private {
			t.Errorf("IsPrivateURL(%q) = %v, want %v", c.raw, got, c.private)
		}
	}
}
