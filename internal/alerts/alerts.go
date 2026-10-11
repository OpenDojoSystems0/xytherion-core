package alerts

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/xytherion/core/pkg/metrics"
)

type Config struct {
	CPUPercent  float64 // fire after SustainSecs above this
	MemPercent  float64
	DiskPercent float64
	LoadPerCPU  float64
	SustainSecs int // consecutive ticks above threshold before alerting
}

func DefaultConfig() Config {
	return Config{
		CPUPercent:  85,
		MemPercent:  90,
		DiskPercent: 90,
		LoadPerCPU:  2.0,
		SustainSecs: 10,
	}
}

const historyMax = 100

type Engine struct {
	mu       sync.RWMutex
	active   map[string]*metrics.Alert
	counters map[string]int
	history  []metrics.Alert
	cfg      Config
}

func New(cfg Config) *Engine {
	return &Engine{
		active:   make(map[string]*metrics.Alert),
		counters: make(map[string]int),
		cfg:      cfg,
	}
}

// Check evaluates a snapshot and returns alerts that just fired or cleared.
func (e *Engine) Check(snap metrics.Snapshot) []metrics.Alert {
	var events []metrics.Alert

	events = append(events, e.eval("cpu",
		snap.CPU.Percent, e.cfg.CPUPercent,
		"CPU élevé",
		fmt.Sprintf("CPU à %.1f%% (seuil %.0f%%)", snap.CPU.Percent, e.cfg.CPUPercent),
		metrics.AlertWarning)...)

	events = append(events, e.eval("memory",
		snap.Memory.Percent, e.cfg.MemPercent,
		"Mémoire saturée",
		fmt.Sprintf("RAM à %.1f%% (seuil %.0f%%)", snap.Memory.Percent, e.cfg.MemPercent),
		metrics.AlertCritical)...)

	loadPerCore := 0.0
	if snap.CPU.Cores > 0 {
		loadPerCore = snap.Load[0] / float64(snap.CPU.Cores)
	}
	events = append(events, e.eval("load",
		loadPerCore, e.cfg.LoadPerCPU,
		"Charge système élevée",
		fmt.Sprintf("Load %.2f par cœur (seuil %.1f)", loadPerCore, e.cfg.LoadPerCPU),
		metrics.AlertWarning)...)

	presentDisks := make(map[string]bool, len(snap.Disk))
	for _, d := range snap.Disk {
		id := "disk:" + d.Mountpoint
		presentDisks[id] = true
		events = append(events, e.eval(id,
			d.Percent, e.cfg.DiskPercent,
			"Disque plein",
			fmt.Sprintf("Disque %s à %.1f%% (seuil %.0f%%)", d.Mountpoint, d.Percent, e.cfg.DiskPercent),
			metrics.AlertCritical)...)
	}

	// Clear stale disk alerts for mountpoints that have disappeared.
	e.mu.Lock()
	for id, a := range e.active {
		if strings.HasPrefix(id, "disk:") && !presentDisks[id] {
			now := time.Now()
			a.Active = false
			a.ClearedAt = &now
			e.addHistory(*a)
			events = append(events, *a)
			delete(e.active, id)
			delete(e.counters, id)
		}
	}
	e.mu.Unlock()

	return events
}

func (e *Engine) eval(id string, value, threshold float64, metric, msg string, severity metrics.AlertSeverity) []metrics.Alert {
	e.mu.Lock()
	defer e.mu.Unlock()

	var events []metrics.Alert

	if value >= threshold {
		e.counters[id]++
		if e.counters[id] == e.cfg.SustainSecs {
			// just crossed the sustained threshold — fire
			a := &metrics.Alert{
				ID:        id,
				Metric:    metric,
				Message:   msg,
				Value:     value,
				Threshold: threshold,
				Severity:  severity,
				Active:    true,
				FiredAt:   time.Now(),
			}
			e.active[id] = a
			e.addHistory(*a)
			events = append(events, *a)
		} else if e.counters[id] > e.cfg.SustainSecs {
			// update live value on existing alert
			if a, ok := e.active[id]; ok {
				a.Value = value
				a.Message = msg
			}
		}
	} else {
		if _, firing := e.active[id]; firing {
			// just cleared
			a := e.active[id]
			now := time.Now()
			a.Active = false
			a.ClearedAt = &now
			e.addHistory(*a)
			events = append(events, *a)
			delete(e.active, id)
		}
		e.counters[id] = 0
	}

	return events
}

func (e *Engine) Active() []metrics.Alert {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]metrics.Alert, 0, len(e.active))
	for _, a := range e.active {
		out = append(out, *a)
	}
	return out
}

func (e *Engine) History() []metrics.Alert {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]metrics.Alert, len(e.history))
	copy(out, e.history)
	return out
}

func (e *Engine) addHistory(a metrics.Alert) {
	e.history = append(e.history, a)
	if len(e.history) > historyMax {
		e.history = e.history[len(e.history)-historyMax:]
	}
}
