package httpmon

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/xytherion/core/pkg/metrics"
	"github.com/xytherion/core/pkg/safenet"
)

var httpClient = &http.Client{
	Timeout:   10 * time.Second,
	Transport: safenet.Transport(),
	// Prevent SSRF via redirect: only allow same-host redirects (e.g. http→https),
	// block cross-host redirects that could reach internal services.
	// The safenet transport re-validates the resolved IP on every dial,
	// so even same-host redirects are checked at connect time.
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("too many redirects")
		}
		if req.URL.Hostname() != via[0].URL.Hostname() {
			return fmt.Errorf("cross-host redirect denied")
		}
		return nil
	},
}

type Monitor struct {
	mu      sync.RWMutex
	urls    []string
	results map[string]metrics.HTTPCheck
	notify  func(metrics.HTTPCheck)
}

func New(notify func(metrics.HTTPCheck)) *Monitor {
	return &Monitor{
		results: make(map[string]metrics.HTTPCheck),
		notify:  notify,
	}
}

func (m *Monitor) Add(rawURL string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.urls {
		if u == rawURL {
			return
		}
	}
	m.urls = append(m.urls, rawURL)
}

// TryAdd adds rawURL only if the monitor count is below max. Returns false if at capacity.
func (m *Monitor) TryAdd(rawURL string, max int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.urls {
		if u == rawURL {
			return true // already monitored
		}
	}
	if len(m.urls) >= max {
		return false
	}
	m.urls = append(m.urls, rawURL)
	return true
}

func (m *Monitor) Remove(rawURL string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	filtered := m.urls[:0]
	for _, u := range m.urls {
		if u != rawURL {
			filtered = append(filtered, u)
		}
	}
	m.urls = filtered
	delete(m.results, rawURL)
}

func (m *Monitor) URLs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cp := make([]string, len(m.urls))
	copy(cp, m.urls)
	return cp
}

func (m *Monitor) Results() []metrics.HTTPCheck {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]metrics.HTTPCheck, 0, len(m.results))
	for _, r := range m.results {
		out = append(out, r)
	}
	return out
}

// Run checks all URLs every interval; call in a goroutine.
func (m *Monitor) Run(interval time.Duration) {
	m.checkAll()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		m.checkAll()
	}
}

func (m *Monitor) checkAll() {
	urls := m.URLs()
	var wg sync.WaitGroup
	for _, u := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			result := Check(u)
			m.mu.Lock()
			m.results[u] = result
			m.mu.Unlock()
			if m.notify != nil {
				m.notify(result)
			}
		}(u)
	}
	wg.Wait()
}

func Check(rawURL string) metrics.HTTPCheck {
	start := time.Now()
	result := metrics.HTTPCheck{URL: rawURL, CheckedAt: start}

	resp, err := httpClient.Get(rawURL)
	result.LatencyMS = time.Since(start).Milliseconds()

	if err != nil {
		result.Up = false
		result.Error = err.Error()
		return result
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) //nolint:errcheck
		resp.Body.Close()
	}()

	result.Status = resp.StatusCode
	result.Up = resp.StatusCode < 400

	// HTTPS responses carry the peer certificate: no second connection needed
	// (a separate TLS dial would bypass the SSRF-safe transport).
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		days := int(time.Until(cert.NotAfter).Hours() / 24)
		result.SSLDays = &days
	}

	return result
}
