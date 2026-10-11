package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestServesDashboard(t *testing.T) {
	rec := get(t, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<html") {
		t.Fatal("GET / did not return the dashboard HTML")
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("page Cache-Control = %q, want no-cache", got)
	}
}

func TestServesStatusPage(t *testing.T) {
	if rec := get(t, "/status/"); rec.Code != http.StatusOK {
		t.Fatalf("GET /status/ = %d, want 200", rec.Code)
	}
}

func TestUnknownPathIs404(t *testing.T) {
	rec := get(t, "/does-not-exist")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /does-not-exist = %d, want 404", rec.Code)
	}
}

// The embedded export must include _next/ (dropped by go:embed without "all:").
func TestEmbedsNextAssets(t *testing.T) {
	entries, err := dist.ReadDir("dist/_next/static")
	if err != nil || len(entries) == 0 {
		t.Fatalf("dist/_next/static missing from the embedded dashboard: %v", err)
	}
}

func TestRejectsWrites(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST / = %d, want 405", rec.Code)
	}
}
