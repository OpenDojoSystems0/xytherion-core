package server

import (
	"testing"
)

func TestValidateHTTPURL(t *testing.T) {
	cases := []struct {
		raw string
		ok  bool
	}{
		{"https://example.com", true},
		{"http://example.com/path?q=1", true},
		{"http://192.0.2.1:8080/", true},
		{"ftp://example.com", false},   // wrong scheme
		{"file:///etc/passwd", false},  // wrong scheme
		{"", false},                    // empty
		{"://no-scheme", false},        // malformed
		{"https://", false},            // missing host
		{"javascript:alert(1)", false}, // wrong scheme
		{"data:text/plain,hi", false},  // wrong scheme
	}
	for _, c := range cases {
		err := validateHTTPURL(c.raw)
		if (err == nil) != c.ok {
			t.Errorf("validateHTTPURL(%q): got err=%v, want ok=%v", c.raw, err, c.ok)
		}
	}
}
