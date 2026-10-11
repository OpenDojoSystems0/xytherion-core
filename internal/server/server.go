package server

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/xytherion/core/internal/alerts"
	"github.com/xytherion/core/internal/collector"
	"github.com/xytherion/core/internal/discovery"
	"github.com/xytherion/core/internal/firewall"
	"github.com/xytherion/core/internal/history"
	"github.com/xytherion/core/internal/httpmon"
	"github.com/xytherion/core/internal/procdna"
	"github.com/xytherion/core/internal/procfp"
	"github.com/xytherion/core/internal/scanner"
	"github.com/xytherion/core/internal/selfupdate"
	"github.com/xytherion/core/internal/sshaudit"
	"github.com/xytherion/core/internal/storage"
	"github.com/xytherion/core/internal/store"
	"github.com/xytherion/core/internal/ui"
	"github.com/xytherion/core/internal/webhook"
	"github.com/xytherion/core/pkg/metrics"
	"github.com/xytherion/core/pkg/safenet"
)

type sseEvent struct {
	name string
	data []byte
}

type Server struct {
	port         int
	interval     time.Duration
	hostname     string
	corsOrigins  []string
	token        string   // optional Bearer token; empty = loopback-only access
	allowedHosts []string // extra Host header values accepted (XYTHERION_ALLOWED_HOSTS)
	allowRemote  bool     // XYTHERION_ALLOW_REMOTE=1: allow LAN access without a token
	ring         *store.RingBuffer
	alerts       *alerts.Engine
	httpmon      *httpmon.Monitor
	webhooks     *webhook.Manager
	fingerprints *procfp.Manager
	discovery    *discovery.Manager
	dataStore    *storage.Store
	trends       *history.Store // 1-minute points, 7 days (free plan)
	updater      *selfupdate.Updater
	autoUpdate   bool // XYTHERION_AUTO_UPDATE=1: install updates without asking

	updMu        sync.Mutex
	updLatest    *selfupdate.Release // verified newer release, nil when up to date
	updErr       string
	updCheckedAt time.Time
	updApplying  bool
	version      string

	mu   sync.RWMutex
	subs map[chan sseEvent]struct{}

	scanMu            sync.RWMutex
	lastScan          *metrics.ScanResult
	lastScanAt        time.Time
	lastProcAnomalies []metrics.ProcAnomaly
	lastDNAViolations []procdna.Violation
}

func New(port int, interval time.Duration, ringSize int, corsOrigin string, version string) *Server {
	h := hostname()
	agentID := fmt.Sprintf("%s-%d", h, port)
	osName := runtime.GOOS

	var origins []string
	for _, o := range strings.Split(corsOrigin, ",") {
		if o = strings.TrimSpace(o); o != "" {
			origins = append(origins, o)
		}
	}

	dataFile := os.Getenv("XYTHERION_DATA_FILE")
	if dataFile == "" {
		dataFile = storage.DefaultPath()
	}

	s := &Server{
		port:         port,
		interval:     interval,
		hostname:     h,
		corsOrigins:  origins,
		token:        os.Getenv("XYTHERION_TOKEN"),
		allowedHosts: splitList(os.Getenv("XYTHERION_ALLOWED_HOSTS")),
		allowRemote:  os.Getenv("XYTHERION_ALLOW_REMOTE") == "1",
		ring:         store.NewRingBuffer(ringSize),
		alerts:       alerts.New(alerts.DefaultConfig()),
		webhooks:     webhook.NewManager(),
		fingerprints: procfp.NewManager(),
		dataStore:    storage.New(dataFile),
		trends:       history.New(filepath.Join(filepath.Dir(dataFile), "history.json"), history.FreeRetention),
		subs:         make(map[chan sseEvent]struct{}),
		version:      version,
	}
	s.httpmon = httpmon.New(func(check metrics.HTTPCheck) {
		s.fanout("http_check", check)
	})
	s.discovery = discovery.NewManager(agentID, h, port, osName, func(peers []discovery.Peer) {
		s.fanout("topology", peers)
	})
	s.loadPersistedData()
	if err := s.trends.Load(); err != nil {
		log.Printf("[history] load error: %v", err)
	}

	// Updates come from the official GitHub releases, or from a self-hosted
	// signed manifest (XYTHERION_UPDATE_URL). Either way they must carry the
	// Xytherion signature.
	s.updater = selfupdate.New(os.Getenv("XYTHERION_UPDATE_URL"), version)
	s.autoUpdate = os.Getenv("XYTHERION_AUTO_UPDATE") == "1"
	if err := s.updater.Enabled(); err != nil {
		log.Printf("[selfupdate] %v", err)
	}
	switch {
	case s.token != "":
		log.Println("[auth] token authentication enabled")
	case s.allowRemote:
		log.Println("[auth] WARNING: XYTHERION_ALLOW_REMOTE=1 — any host on the network can read and change this agent")
	default:
		log.Println("[auth] no XYTHERION_TOKEN: API restricted to this machine (set a token to allow remote access)")
	}
	return s
}

func splitList(raw string) []string {
	var out []string
	for _, v := range strings.Split(raw, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, strings.ToLower(v))
		}
	}
	return out
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func (s *Server) Run() {
	go s.collect()
	go s.scanLoop()
	go s.httpmon.Run(30 * time.Second)
	go s.discovery.Run(!s.localOnly())
	go s.shutdownWatcher()
	go s.saveTrendsLoop()
	if s.updater.Enabled() == nil {
		go s.updateLoop()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/stream", s.handleStream)
	mux.HandleFunc("/api/metrics", s.handleMetrics)
	mux.HandleFunc("/api/history", s.handleHistory)
	mux.HandleFunc("/api/trends", s.handleTrends)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/alerts/history", s.handleAlertsHistory)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/scan/run", s.handleScanRun)
	mux.HandleFunc("/api/monitors", s.handleMonitors)
	mux.HandleFunc("/api/ssh", s.handleSSH)
	mux.HandleFunc("/api/firewall", s.handleFirewall)
	mux.HandleFunc("/api/ports", s.handlePorts)
	mux.HandleFunc("/api/webhooks", s.handleWebhooks)
	mux.HandleFunc("/api/topology", s.handleTopology)
	mux.HandleFunc("/api/update", s.handleUpdate)
	mux.HandleFunc("/health", s.handleHealth)
	// Everything else is the embedded dashboard: http://localhost:9001/
	mux.Handle("/", ui.Handler())

	srv := &http.Server{
		Handler:           s.authMiddleware(securityHeaders(mux)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		MaxHeaderBytes:    64 << 10,
		IdleTimeout:       120 * time.Second,
	}

	// Without a token the API only serves this machine, so do not even open
	// the port to the network: listen on loopback only (IPv4 and IPv6).
	addrs := []string{fmt.Sprintf(":%d", s.port)}
	if s.localOnly() {
		addrs = []string{fmt.Sprintf("127.0.0.1:%d", s.port), fmt.Sprintf("[::1]:%d", s.port)}
	}
	var listeners []net.Listener
	for i, a := range addrs {
		l, err := net.Listen("tcp", a)
		if err != nil {
			if i == 0 {
				log.Fatalf("server: %v", err)
			}
			log.Printf("server: %v (ignored)", err) // e.g. IPv6 disabled
			continue
		}
		listeners = append(listeners, l)
	}
	scope := "all interfaces"
	if s.localOnly() {
		scope = "this machine only (set XYTHERION_TOKEN for remote access)"
	}
	log.Printf("xytherion %s listening on port %d — %s  (hostname: %s)", s.version, s.port, scope, s.hostname)
	log.Printf("dashboard: http://localhost:%d", s.port)

	errc := make(chan error, len(listeners))
	for _, l := range listeners {
		go func(l net.Listener) { errc <- srv.Serve(l) }(l)
	}
	log.Fatalf("server: %v", <-errc)
}

// localOnly reports whether the agent must stay reachable from this machine only.
func (s *Server) localOnly() bool {
	return s.token == "" && !s.allowRemote
}

/* ── Collection loop ───────────────────────────────────────────── */

func (s *Server) collect() {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for range ticker.C {
		snap, err := collector.Collect(s.hostname)
		if err != nil {
			log.Printf("collect: %v", err)
			continue
		}
		s.ring.Push(*snap)
		s.trends.Add(*snap)
		s.fanout("metric", snap)

		// DNA check — store latest for initial SSE burst on new connections
		if violations := procdna.Check(snap.Procs); len(violations) > 0 {
			s.scanMu.Lock()
			s.lastDNAViolations = violations
			s.scanMu.Unlock()
			s.fanout("dna_alert", violations)
		}

		if anomalies := s.fingerprints.Update(snap.Procs); len(anomalies) > 0 {
			s.scanMu.Lock()
			s.lastProcAnomalies = anomalies
			s.scanMu.Unlock()
			s.fanout("proc_anomaly", anomalies)
		}

		if fired := s.alerts.Check(*snap); len(fired) > 0 {
			for _, a := range fired {
				s.fanout("alert", a)
				s.webhooks.NotifyAlert(s.hostname, a)
				if a.Active {
					log.Printf("[alert] %s: %s", a.Severity, a.Message)
				} else {
					log.Printf("[alert cleared] %s", a.Metric)
				}
			}
		}
	}
}

/* ── Security scan loop ────────────────────────────────────────── */

func (s *Server) scanLoop() {
	s.runScan()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.runScan()
	}
}

func (s *Server) runScan() {
	log.Println("[scan] scanning localhost ports…")
	result := scanner.Scan("127.0.0.1")
	s.scanMu.Lock()
	s.lastScan = &result
	s.lastScanAt = time.Now()
	s.scanMu.Unlock()
	s.fanout("scan", result)
	log.Printf("[scan] done in %dms — %d ports open", result.DurationMS, len(result.Ports))
}

/* ── Shutdown watcher ──────────────────────────────────────────── */

func (s *Server) shutdownWatcher() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh
	log.Printf("[shutdown] graceful shutdown initiated")
	s.persistData()
	if err := s.trends.Save(); err != nil {
		log.Printf("[history] save error: %v", err)
	}
	s.fanout("shutdown", map[string]interface{}{
		"graceful": true,
		"hostname": s.hostname,
	})
	time.Sleep(500 * time.Millisecond)
	os.Exit(0)
}

/* ── SSE fanout ────────────────────────────────────────────────── */

func (s *Server) fanout(event string, payload interface{}) {
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	ev := sseEvent{name: event, data: data}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for ch := range s.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

const maxSubscribers = 32

func (s *Server) subscribe() chan sseEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.subs) >= maxSubscribers {
		return nil
	}
	ch := make(chan sseEvent, 16)
	s.subs[ch] = struct{}{}
	return ch
}

func (s *Server) unsubscribe(ch chan sseEvent) {
	s.mu.Lock()
	delete(s.subs, ch)
	s.mu.Unlock()
}

/* ── HTTP handlers ─────────────────────────────────────────────── */

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := s.subscribe()
	if ch == nil {
		http.Error(w, "too many subscribers", http.StatusServiceUnavailable)
		return
	}
	defer s.unsubscribe(ch)

	if last, ok := s.ring.Latest(); ok {
		writeEvent(w, flusher, "metric", last)
	}
	if active := s.alerts.Active(); len(active) > 0 {
		writeEvent(w, flusher, "alerts_state", active)
	}
	if hist := s.alerts.History(); len(hist) > 0 {
		// reverse to newest-first so the client matches live prepend order
		for i, j := 0, len(hist)-1; i < j; i, j = i+1, j-1 {
			hist[i], hist[j] = hist[j], hist[i]
		}
		writeEvent(w, flusher, "alerts_history", hist)
	}
	s.scanMu.RLock()
	if s.lastScan != nil {
		writeEvent(w, flusher, "scan", *s.lastScan)
	}
	s.scanMu.RUnlock()
	if results := s.httpmon.Results(); len(results) > 0 {
		writeEvent(w, flusher, "http_checks", results)
	}
	if peers := s.discovery.Peers(); len(peers) > 0 {
		writeEvent(w, flusher, "topology", peers)
	}
	s.scanMu.RLock()
	anomalies := s.lastProcAnomalies
	dnaViolations := s.lastDNAViolations
	s.scanMu.RUnlock()
	if len(anomalies) > 0 {
		writeEvent(w, flusher, "proc_anomaly", anomalies)
	}
	if len(dnaViolations) > 0 {
		writeEvent(w, flusher, "dna_alert", dnaViolations)
	}

	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.name, ev.data)
			flusher.Flush()
		}
	}
}

func writeEvent(w http.ResponseWriter, f http.Flusher, event string, v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
	f.Flush()
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	snap, ok := s.ring.Latest()
	if !ok {
		http.Error(w, "no data yet", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, snap)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	n := 60
	if raw := r.URL.Query().Get("n"); raw != "" {
		if v, _ := strconv.Atoi(raw); v > 0 && v <= 3600 {
			n = v
		}
	}
	writeJSON(w, s.ring.Last(n))
}

// GET /api/trends?range=1h|24h|7d — one averaged point per minute.
// The free plan keeps 7 days; longer ranges are capped by the store.
func (s *Server) handleTrends(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	ranges := map[string]time.Duration{"1h": time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour}
	d, ok := ranges[r.URL.Query().Get("range")]
	if !ok {
		d = 24 * time.Hour
	}
	writeJSON(w, map[string]interface{}{
		"retention_hours": int(s.trends.Retention().Hours()),
		"points":          s.trends.Since(d),
	})
}

// saveTrendsLoop flushes the minute history to disk every 5 minutes.
func (s *Server) saveTrendsLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		if err := s.trends.Save(); err != nil {
			log.Printf("[history] save error: %v", err)
		}
	}
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	writeJSON(w, s.alerts.Active())
}

func (s *Server) handleAlertsHistory(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	writeJSON(w, s.alerts.History())
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	s.scanMu.RLock()
	defer s.scanMu.RUnlock()
	if s.lastScan == nil {
		http.Error(w, "scan not yet available", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, *s.lastScan)
}

func (s *Server) handleScanRun(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.scanMu.Lock()
	elapsed := time.Since(s.lastScanAt)
	if elapsed < 30*time.Second {
		s.scanMu.Unlock()
		http.Error(w, "scan cooldown: please wait before scanning again", http.StatusTooManyRequests)
		return
	}
	s.lastScanAt = time.Now() // claim the slot before releasing the lock
	s.scanMu.Unlock()
	go s.runScan()
	writeJSON(w, map[string]string{"status": "scanning"})
}

func (s *Server) handleMonitors(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	rawURL := r.URL.Query().Get("url")

	switch r.Method {
	case http.MethodGet, "":
		writeJSON(w, map[string]interface{}{
			"urls":    s.httpmon.URLs(),
			"results": s.httpmon.Results(),
		})
	case http.MethodPost:
		if rawURL == "" || len(rawURL) > 2048 {
			http.Error(w, "missing or too long url parameter (max 2048)", http.StatusBadRequest)
			return
		}
		if err := validateHTTPURL(rawURL); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if safenet.IsPrivateURL(rawURL) {
			http.Error(w, "monitor URL must not target private or reserved networks", http.StatusBadRequest)
			return
		}
		if !s.httpmon.TryAdd(rawURL, 100) {
			http.Error(w, "monitor limit reached (max 100)", http.StatusBadRequest)
			return
		}
		s.fanout("http_checks", s.httpmon.Results())
		go s.persistData()
		writeJSON(w, map[string]string{"status": "added", "url": rawURL})
	case http.MethodDelete:
		if rawURL == "" {
			http.Error(w, "missing url parameter", http.StatusBadRequest)
			return
		}
		s.httpmon.Remove(rawURL)
		s.fanout("http_checks", s.httpmon.Results())
		go s.persistData()
		writeJSON(w, map[string]string{"status": "removed"})
	case http.MethodOptions:
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSSH(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	logins := sshaudit.LastLogins(20)
	if logins == nil {
		logins = []metrics.SSHLogin{}
	}
	writeJSON(w, logins)
}

func (s *Server) handleFirewall(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	writeJSON(w, firewall.Status())
}

func (s *Server) handlePorts(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	writeJSON(w, scanner.ListeningPorts())
}

// GET  /api/webhooks            — list
// POST /api/webhooks            — add (body: Webhook JSON)
// DELETE /api/webhooks?id=...   — remove
func (s *Server) handleWebhooks(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	switch r.Method {
	case http.MethodGet, "":
		writeJSON(w, s.webhooks.List())
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		var wh webhook.Webhook
		if err := json.NewDecoder(r.Body).Decode(&wh); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if len(wh.Name) > 128 || len(wh.ID) > 64 || len(wh.URL) > 2048 {
			http.Error(w, "webhook field too long (name ≤ 128, id ≤ 64, url ≤ 2048)", http.StatusBadRequest)
			return
		}
		switch wh.Type {
		case webhook.TypeDiscord, webhook.TypeSlack, webhook.TypeGeneric:
		case "":
			wh.Type = webhook.TypeGeneric
		default:
			http.Error(w, "webhook type must be discord, slack or generic", http.StatusBadRequest)
			return
		}
		if err := validateHTTPURL(wh.URL); err != nil {
			http.Error(w, "webhook URL: "+err.Error(), http.StatusBadRequest)
			return
		}
		if safenet.IsPrivateURL(wh.URL) {
			http.Error(w, "webhook URL must not target private or reserved networks", http.StatusBadRequest)
			return
		}
		if wh.ID == "" {
			wh.ID = fmt.Sprintf("%d", time.Now().UnixNano())
		}
		if !s.webhooks.TryAdd(wh, 50) {
			http.Error(w, "webhook limit reached (max 50)", http.StatusBadRequest)
			return
		}
		go s.persistData()
		writeJSON(w, wh)
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		s.webhooks.Remove(id)
		go s.persistData()
		writeJSON(w, map[string]string{"status": "removed"})
	case http.MethodOptions:
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET /api/topology — liste des peers découverts sur le LAN
func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, s.discovery.Peers())
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	writeJSON(w, map[string]string{
		"status":   "ok",
		"hostname": s.hostname,
		"version":  s.version,
	})
}

/* ── Self-update ───────────────────────────────────────────────── */

// updateLoop checks for a new release shortly after start, then every 6 h.
// With XYTHERION_AUTO_UPDATE=1 it installs it; otherwise the dashboard shows it.
func (s *Server) updateLoop() {
	time.Sleep(time.Minute)
	for {
		if rel := s.checkUpdate(); rel != nil && s.autoUpdate {
			log.Printf("[selfupdate] auto-update to %s", rel.Version)
			if err := s.applyUpdate(rel); err != nil {
				log.Printf("[selfupdate] apply: %v", err)
			}
		}
		time.Sleep(6 * time.Hour)
	}
}

func (s *Server) checkUpdate() *selfupdate.Release {
	rel, err := s.updater.Check()
	s.updMu.Lock()
	defer s.updMu.Unlock()
	s.updCheckedAt = time.Now()
	s.updLatest, s.updErr = rel, ""
	if err != nil {
		s.updErr = err.Error()
		log.Printf("[selfupdate] check: %v", err)
	} else if rel != nil {
		log.Printf("[selfupdate] %s available (current %s)", rel.Version, s.version)
	}
	return rel
}

// applyUpdate saves state, then replaces the binary and re-executes it.
// It returns only on failure.
func (s *Server) applyUpdate(rel *selfupdate.Release) error {
	s.updMu.Lock()
	if s.updApplying {
		s.updMu.Unlock()
		return fmt.Errorf("une mise à jour est déjà en cours")
	}
	s.updApplying = true
	s.updMu.Unlock()
	defer func() { s.updMu.Lock(); s.updApplying = false; s.updMu.Unlock() }()

	s.persistData()
	if err := s.trends.Save(); err != nil {
		log.Printf("[history] save error: %v", err)
	}
	s.fanout("shutdown", map[string]interface{}{"graceful": true, "hostname": s.hostname, "reason": "update"})
	time.Sleep(300 * time.Millisecond)
	return s.updater.Apply(rel)
}

// GET  /api/update — current version, available update, how to install it.
// POST /api/update — check now and install the verified update if any.
func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	exe, _ := selfupdate.Executable()
	status := func(latest *selfupdate.Release) map[string]interface{} {
		s.updMu.Lock()
		defer s.updMu.Unlock()
		out := map[string]interface{}{
			"current":    s.version,
			"available":  latest != nil,
			"managed_by": selfupdate.ManagedBy(exe),
			"auto":       s.autoUpdate,
			"error":      s.updErr,
		}
		if err := s.updater.Enabled(); err != nil {
			out["error"] = err.Error()
		}
		if latest != nil {
			out["latest"] = latest.Version
		}
		if !s.updCheckedAt.IsZero() {
			out["checked_at"] = s.updCheckedAt
		}
		return out
	}

	switch r.Method {
	case http.MethodGet, "":
		s.updMu.Lock()
		latest := s.updLatest
		s.updMu.Unlock()
		writeJSON(w, status(latest))
	case http.MethodPost:
		if err := s.updater.Enabled(); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		rel := s.checkUpdate()
		if rel == nil {
			writeJSON(w, status(nil))
			return
		}
		if m := selfupdate.ManagedBy(exe); m != "" {
			http.Error(w, "installé via Homebrew : mettez à jour avec « brew upgrade xytherion »", http.StatusConflict)
			return
		}
		writeJSON(w, map[string]string{"status": "updating", "version": rel.Version})
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		go func() {
			if err := s.applyUpdate(rel); err != nil {
				log.Printf("[selfupdate] apply: %v", err)
				s.updMu.Lock()
				s.updErr = err.Error()
				s.updMu.Unlock()
				s.fanout("update_error", map[string]string{"error": err.Error()})
			}
		}()
	case http.MethodOptions:
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			// The static dashboard needs inline scripts (Next.js export) and may
			// connect to other agents of the fleet, hence connect-src http(s).
			w.Header().Set("Content-Security-Policy",
				"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "+
					"img-src 'self' data:; connect-src 'self' http: https:; frame-ancestors 'none'; "+
					"base-uri 'self'; form-action 'self'; object-src 'none'")
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (s *Server) setCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	allowed := ""
	if s.token != "" && origin != "" {
		// Token-protected: any dashboard (e.g. a fleet view hosted by another
		// agent) may read, it still has to present the token.
		allowed = origin
	}
	for _, o := range s.corsOrigins {
		if o == "*" {
			allowed = "*"
			break
		}
		if o == origin {
			allowed = origin
			break
		}
	}
	if allowed != "" {
		w.Header().Set("Access-Control-Allow-Origin", allowed)
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Vary", "Origin")
}

// validateHTTPURL returns an error if u is not a safe http/https URL.
func validateHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("URL must use http or https scheme")
	}
	if u.Host == "" {
		return fmt.Errorf("URL must have a host")
	}
	return nil
}

/* ── Security guard ────────────────────────────────────────────── */

// authMiddleware protects every request, in this order:
//  1. Host allow-list    — blocks DNS-rebinding (evil.com resolving to 127.0.0.1).
//  2. CORS preflights    — answered without credentials, as browsers require.
//  3. Same-origin writes — blocks CSRF: a web page cannot POST/DELETE here.
//  4. Authentication     — /api/ needs the token; without one, only this
//     machine may call the API (opt out with XYTHERION_ALLOW_REMOTE=1).
//
// The token can be passed as Authorization: Bearer <token> or ?token=<token>
// (query param needed for EventSource which cannot set request headers).
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hostAllowed(r.Host) {
			http.Error(w, "host not allowed (set XYTHERION_ALLOWED_HOSTS to add it)", http.StatusMisdirectedRequest)
			return
		}
		// Browsers send CORS preflights without credentials; answer them directly.
		if r.Method == http.MethodOptions {
			s.setCORS(w, r)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if isWrite(r.Method) && !s.writeOriginAllowed(r) {
			http.Error(w, "cross-site request blocked", http.StatusForbidden)
			return
		}
		// /health and the dashboard's static files carry no data; the dashboard
		// then asks for the token and sends it with every /api request.
		if r.URL.Path == "/health" || !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		if s.token == "" {
			if s.allowRemote || isLoopback(r.RemoteAddr) {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, "remote access requires XYTHERION_TOKEN on the agent", http.StatusForbidden)
			return
		}
		tok := r.URL.Query().Get("token")
		if tok == "" {
			if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				tok = strings.TrimPrefix(auth, "Bearer ")
			}
		}
		if subtle.ConstantTimeCompare([]byte(tok), []byte(s.token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isWrite(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

// hostAllowed accepts IP literals, localhost, this machine's name, mDNS .local
// names and anything listed in XYTHERION_ALLOWED_HOSTS. A public DNS name
// pointing at the agent is refused unless explicitly allowed.
func (s *Server) hostAllowed(hostHeader string) bool {
	host := hostHeader
	if h, _, err := net.SplitHostPort(hostHeader); err == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "" {
		return false
	}
	if net.ParseIP(host) != nil || host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return true
	}
	if self := strings.ToLower(s.hostname); self != "" &&
		(host == self || host == strings.TrimSuffix(self, ".local") || strings.HasPrefix(self, host+".")) {
		return true
	}
	for _, allowed := range s.allowedHosts {
		if host == allowed {
			return true
		}
	}
	return false
}

// writeOriginAllowed lets state-changing requests through only from the
// agent's own dashboard, a configured CORS origin, or non-browser clients
// (curl, scripts) that send no Origin and no cross-site fetch metadata.
func (s *Server) writeOriginAllowed(r *http.Request) bool {
	// With a token, a foreign page cannot forge requests: browsers never attach
	// the token on their own. Fleet dashboards on other agents can write.
	if s.token != "" {
		return true
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return r.Header.Get("Sec-Fetch-Site") != "cross-site"
	}
	if u, err := url.Parse(origin); err == nil && strings.EqualFold(u.Host, r.Host) {
		return true
	}
	for _, o := range s.corsOrigins {
		if o == "*" || o == origin {
			return true
		}
	}
	return false
}

func isLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

/* ── Persistence ───────────────────────────────────────────────── */

func (s *Server) loadPersistedData() {
	d, err := s.dataStore.Load()
	if err != nil {
		log.Printf("[storage] load error: %v", err)
		return
	}
	for _, u := range d.Monitors {
		s.httpmon.TryAdd(u, 100)
	}
	for _, h := range d.Webhooks {
		s.webhooks.TryAdd(webhook.Webhook{
			ID: h.ID, Name: h.Name, URL: h.URL,
			Type: webhook.WebhookType(h.Type), Enabled: h.Enabled,
		}, 50)
	}
	if len(d.Monitors)+len(d.Webhooks) > 0 {
		log.Printf("[storage] loaded %d monitors, %d webhooks from %s",
			len(d.Monitors), len(d.Webhooks), s.dataStore.Path())
	}
}

func (s *Server) persistData() {
	urls := s.httpmon.URLs()
	hooks := s.webhooks.List()
	raw := make([]storage.RawHook, len(hooks))
	for i, h := range hooks {
		raw[i] = storage.RawHook{
			ID: h.ID, Name: h.Name, URL: h.URL,
			Type: string(h.Type), Enabled: h.Enabled,
		}
	}
	if err := s.dataStore.Save(storage.Data{Monitors: urls, Webhooks: raw}); err != nil {
		log.Printf("[storage] save error: %v", err)
	}
}
