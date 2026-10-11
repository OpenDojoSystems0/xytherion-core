package procfp

import (
	"math"
	"sync"

	"github.com/xytherion/core/pkg/metrics"
)

const (
	windowSize = 60  // 1 minute at 1s interval
	evictAfter = 120 // evict entry not seen for 2 minutes (ticks)
)

type sample struct {
	cpu float64
	mem float64
}

type entry struct {
	samples  []sample
	lastTick uint64
}

type Manager struct {
	mu      sync.Mutex
	entries map[string]*entry
	tick    uint64
}

func NewManager() *Manager {
	return &Manager{entries: make(map[string]*entry)}
}

// Update adds new observations for each process and returns anomalies (z-score ≥ 2.0).
// Entries for processes not seen in evictAfter ticks are evicted to prevent unbounded growth.
func (m *Manager) Update(procs []metrics.Process) []metrics.ProcAnomaly {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.tick++

	// Evict stale entries (processes no longer running)
	for name, e := range m.entries {
		if m.tick-e.lastTick > evictAfter {
			delete(m.entries, name)
		}
	}

	var out []metrics.ProcAnomaly
	for _, p := range procs {
		e, ok := m.entries[p.Name]
		if !ok {
			e = &entry{}
			m.entries[p.Name] = e
		}
		e.lastTick = m.tick
		e.samples = append(e.samples, sample{cpu: p.CPU, mem: float64(p.Memory)})
		if len(e.samples) > windowSize {
			e.samples = e.samples[1:]
		}

		n := len(e.samples)
		if n < 10 {
			continue
		}

		var sumCPU, sumMem float64
		for _, s := range e.samples {
			sumCPU += s.cpu
			sumMem += s.mem
		}
		meanCPU := sumCPU / float64(n)
		meanMem := sumMem / float64(n)

		var varCPU, varMem float64
		for _, s := range e.samples {
			varCPU += (s.cpu - meanCPU) * (s.cpu - meanCPU)
			varMem += (s.mem - meanMem) * (s.mem - meanMem)
		}
		stdCPU := math.Sqrt(varCPU / float64(n))
		stdMem := math.Sqrt(varMem / float64(n))

		var zCPU, zMem float64
		if stdCPU > 0.5 {
			zCPU = math.Abs(p.CPU-meanCPU) / stdCPU
		}
		if stdMem > 0.1 {
			zMem = math.Abs(float64(p.Memory)-meanMem) / stdMem
		}

		score := math.Max(zCPU, zMem)
		if score >= 2.0 {
			out = append(out, metrics.ProcAnomaly{
				Name:    p.Name,
				PID:     p.PID,
				Score:   round2(score),
				CPU:     p.CPU,
				MemPct:  p.Memory,
				MeanCPU: round2(meanCPU),
				MeanMem: float32(round2(meanMem)),
			})
		}
	}
	return out
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}
