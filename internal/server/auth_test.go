package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestServer(token string) *Server {
	return &Server{
		token:       token,
		hostname:    "test-host.local",
		corsOrigins: []string{"http://localhost:3092"},
		version:     "v1.2.3",
	}
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
}

// req builds a request as a browser on another LAN machine would send it.
func req(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.Host = "192.168.1.10:9001"
	r.RemoteAddr = "192.168.1.20:51234"
	return r
}

func serve(s *Server, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.authMiddleware(okHandler()).ServeHTTP(rec, r)
	return rec
}

// A browser preflight never carries the token; it must not be rejected,
// otherwise every authenticated dashboard request fails CORS.
func TestAuthLetsPreflightThrough(t *testing.T) {
	s := newTestServer("secret")
	r := req(http.MethodOptions, "/api/metrics")
	r.Header.Set("Origin", "http://localhost:3092")
	r.Header.Set("Access-Control-Request-Headers", "authorization")
	rec := serve(s, r)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3092" {
		t.Fatalf("Allow-Origin = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "Authorization") {
		t.Fatalf("Allow-Headers = %q, must include Authorization", got)
	}
}

func TestAuthRequiresToken(t *testing.T) {
	s := newTestServer("secret")
	cases := []struct {
		name   string
		mutate func(*http.Request)
		want   int
	}{
		{"no token", func(r *http.Request) {}, http.StatusUnauthorized},
		{"bad token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer nope") }, http.StatusUnauthorized},
		{"bearer", func(r *http.Request) { r.Header.Set("Authorization", "Bearer secret") }, http.StatusOK},
		{"query", func(r *http.Request) { q := r.URL.Query(); q.Set("token", "secret"); r.URL.RawQuery = q.Encode() }, http.StatusOK},
	}
	for _, c := range cases {
		r := req(http.MethodGet, "/api/metrics")
		c.mutate(r)
		if rec := serve(s, r); rec.Code != c.want {
			t.Errorf("%s: status = %d, want %d", c.name, rec.Code, c.want)
		}
	}
}

// Without a token the API is reachable from this machine only.
func TestNoTokenIsLoopbackOnly(t *testing.T) {
	s := newTestServer("")

	if rec := serve(s, req(http.MethodGet, "/api/metrics")); rec.Code != http.StatusForbidden {
		t.Errorf("remote without token = %d, want 403", rec.Code)
	}

	local := req(http.MethodGet, "/api/metrics")
	local.Host, local.RemoteAddr = "localhost:9001", "127.0.0.1:50000"
	if rec := serve(s, local); rec.Code != http.StatusOK {
		t.Errorf("loopback without token = %d, want 200", rec.Code)
	}

	s.allowRemote = true
	if rec := serve(s, req(http.MethodGet, "/api/metrics")); rec.Code != http.StatusOK {
		t.Errorf("remote with XYTHERION_ALLOW_REMOTE = %d, want 200", rec.Code)
	}
}

// DNS rebinding: evil.example resolves to 127.0.0.1, the browser sends Host: evil.example.
func TestRejectsUnknownHost(t *testing.T) {
	s := newTestServer("")
	r := req(http.MethodGet, "/api/metrics")
	r.Host, r.RemoteAddr = "evil.example:9001", "127.0.0.1:50000"
	if rec := serve(s, r); rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("rebinding host = %d, want 421", rec.Code)
	}

	for _, h := range []string{"localhost:9001", "127.0.0.1:9001", "[::1]:9001", "192.168.1.10:9001", "test-host.local:9001", "test-host:9001"} {
		if !s.hostAllowed(h) {
			t.Errorf("hostAllowed(%q) = false, want true", h)
		}
	}
	s.allowedHosts = []string{"monitor.example.com"}
	if !s.hostAllowed("monitor.example.com") {
		t.Error("XYTHERION_ALLOWED_HOSTS entry was refused")
	}
}

// CSRF: a random web page posting to the local agent must be refused when no
// token protects it; the agent's own dashboard and curl must still work.
func TestBlocksCrossSiteWrites(t *testing.T) {
	s := newTestServer("")
	local := func(origin, fetchSite string) *http.Request {
		r := req(http.MethodPost, "/api/scan/run")
		r.Host, r.RemoteAddr = "localhost:9001", "127.0.0.1:50000"
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if fetchSite != "" {
			r.Header.Set("Sec-Fetch-Site", fetchSite)
		}
		return r
	}
	cases := []struct {
		name, origin, fetchSite string
		want                    int
	}{
		{"evil origin", "https://evil.example", "", http.StatusForbidden},
		{"cross-site no origin", "", "cross-site", http.StatusForbidden},
		{"own dashboard", "http://localhost:9001", "same-origin", http.StatusOK},
		{"configured dev origin", "http://localhost:3092", "", http.StatusOK},
		{"curl", "", "", http.StatusOK},
	}
	for _, c := range cases {
		if rec := serve(s, local(c.origin, c.fetchSite)); rec.Code != c.want {
			t.Errorf("%s: status = %d, want %d", c.name, rec.Code, c.want)
		}
	}
}

// The dashboard's static files are public; only /api/ needs the token.
func TestDashboardFilesArePublic(t *testing.T) {
	s := newTestServer("secret")
	for _, p := range []string{"/", "/status/", "/_next/static/chunk.js"} {
		if rec := serve(s, req(http.MethodGet, p)); rec.Code != http.StatusOK {
			t.Errorf("GET %s without token = %d, want 200", p, rec.Code)
		}
	}
	if rec := serve(s, req(http.MethodGet, "/api/stream")); rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /api/stream without token = %d, want 401", rec.Code)
	}
}

func TestHealthIsPublicAndReportsVersion(t *testing.T) {
	s := newTestServer("secret")
	rec := httptest.NewRecorder()
	s.authMiddleware(http.HandlerFunc(s.handleHealth)).ServeHTTP(rec, req(http.MethodGet, "/health"))

	if rec.Code != http.StatusOK {
		t.Fatalf("health status = %d, want 200 without token", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"version":"v1.2.3"`) {
		t.Fatalf("health body = %s, want build version", rec.Body.String())
	}
}
