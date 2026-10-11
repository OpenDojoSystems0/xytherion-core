// Package history keeps a long, low-resolution history of the server's key
// metrics: one averaged point per minute, kept for the plan's retention
// (7 days in the free plan) and persisted to disk so it survives restarts.
//
// The 1-second live history (last hour) stays in the in-memory ring buffer;
// this package only stores the downsampled trend.
package history

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/xytherion/core/pkg/metrics"
)

// FreeRetention is how long the open-source agent keeps its history.
const FreeRetention = 7 * 24 * time.Hour

// Point is one minute of averaged metrics.
type Point struct {
	T    int64   `json:"t"`    // minute start, Unix seconds
	CPU  float32 `json:"cpu"`  // %
	Mem  float32 `json:"mem"`  // %
	Disk float32 `json:"disk"` // fullest mounted disk, %
	Load float32 `json:"load"` // 1-min load average
	Send float32 `json:"send"` // MB/s
	Recv float32 `json:"recv"` // MB/s
}

type bucket struct {
	start                            time.Time
	n                                int
	cpu, mem, disk, load, send, recv float64
}

// Store accumulates snapshots into minute points.
type Store struct {
	mu        sync.Mutex
	path      string
	retention time.Duration
	points    []Point
	cur       bucket
	dirty     bool
}

// New returns a store persisted at path (empty path = memory only).
func New(path string, retention time.Duration) *Store {
	return &Store{path: path, retention: retention}
}

// Add feeds one snapshot. When a new minute starts, the previous minute is
// closed into a point.
func (s *Store) Add(snap metrics.Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()

	minute := snap.Time.Truncate(time.Minute)
	if s.cur.n > 0 && !minute.Equal(s.cur.start) {
		s.closeBucket()
	}
	if s.cur.n == 0 {
		s.cur = bucket{start: minute}
	}

	var fullest float64
	for _, d := range snap.Disk {
		if d.Percent > fullest {
			fullest = d.Percent
		}
	}
	s.cur.n++
	s.cur.cpu += snap.CPU.Percent
	s.cur.mem += snap.Memory.Percent
	s.cur.disk += fullest
	s.cur.load += snap.Load[0]
	s.cur.send += snap.NetIO.SendMBs
	s.cur.recv += snap.NetIO.RecvMBs
}

// closeBucket must be called with s.mu held.
func (s *Store) closeBucket() {
	n := float64(s.cur.n)
	s.points = append(s.points, Point{
		T:    s.cur.start.Unix(),
		CPU:  float32(s.cur.cpu / n),
		Mem:  float32(s.cur.mem / n),
		Disk: float32(s.cur.disk / n),
		Load: float32(s.cur.load / n),
		Send: float32(s.cur.send / n),
		Recv: float32(s.cur.recv / n),
	})
	s.cur = bucket{}
	s.dirty = true
	s.pruneLocked(time.Now())
}

func (s *Store) pruneLocked(now time.Time) {
	cutoff := now.Add(-s.retention).Unix()
	i := 0
	for i < len(s.points) && s.points[i].T < cutoff {
		i++
	}
	if i > 0 {
		s.points = append([]Point(nil), s.points[i:]...)
	}
}

// Since returns the points newer than d, oldest first. d is capped at the
// retention, so the free plan never returns more than 7 days.
func (s *Store) Since(d time.Duration) []Point {
	if d <= 0 || d > s.retention {
		d = s.retention
	}
	cutoff := time.Now().Add(-d).Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Point, 0, len(s.points))
	for _, p := range s.points {
		if p.T >= cutoff {
			out = append(out, p)
		}
	}
	return out
}

// Retention reports how far back the store keeps data.
func (s *Store) Retention() time.Duration { return s.retention }

// Load reads the persisted history, dropping anything past the retention.
func (s *Store) Load() error {
	if s.path == "" {
		return nil
	}
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var pts []Point
	if err := json.Unmarshal(data, &pts); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.points = pts
	s.pruneLocked(time.Now())
	return nil
}

// Save writes the history atomically (temp file + rename, mode 0600) when it
// changed since the last save.
func (s *Store) Save() error {
	if s.path == "" {
		return nil
	}
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	data, err := json.Marshal(s.points)
	s.dirty = false
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
