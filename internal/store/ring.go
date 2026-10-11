package store

import (
	"sync"

	"github.com/xytherion/core/pkg/metrics"
)

const defaultRingSize = 3600

type RingBuffer struct {
	items []metrics.Snapshot
	size  int
	head  int
	count int
	mu    sync.RWMutex
}

func NewRingBuffer(size int) *RingBuffer {
	if size <= 0 {
		size = defaultRingSize
	}
	return &RingBuffer{items: make([]metrics.Snapshot, size), size: size}
}

func (r *RingBuffer) Push(s metrics.Snapshot) {
	r.mu.Lock()
	r.items[r.head] = s
	r.head = (r.head + 1) % r.size
	if r.count < r.size {
		r.count++
	}
	r.mu.Unlock()
}

// Last returns the most recent n snapshots in chronological order.
func (r *RingBuffer) Last(n int) []metrics.Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if n > r.count {
		n = r.count
	}
	if n == 0 {
		return nil
	}
	out := make([]metrics.Snapshot, n)
	start := (r.head - n + r.size) % r.size
	for i := 0; i < n; i++ {
		out[i] = r.items[(start+i)%r.size]
	}
	return out
}

func (r *RingBuffer) Latest() (metrics.Snapshot, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.count == 0 {
		return metrics.Snapshot{}, false
	}
	return r.items[(r.head-1+r.size)%r.size], true
}

// All retourne tous les snapshots stockés dans le buffer en ordre chronologique.
func (r *RingBuffer) All() []metrics.Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.count == 0 {
		return nil
	}
	n := r.count
	out := make([]metrics.Snapshot, n)
	start := (r.head - n + r.size) % r.size
	for i := 0; i < n; i++ {
		out[i] = r.items[(start+i)%r.size]
	}
	return out
}
