package history

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/xytherion/core/pkg/metrics"
)

func snap(t time.Time, cpu, mem float64) metrics.Snapshot {
	return metrics.Snapshot{
		Time:   t,
		CPU:    metrics.CPUInfo{Percent: cpu},
		Memory: metrics.MemInfo{Percent: mem},
		Disk:   []metrics.DiskInfo{{Mountpoint: "/", Percent: 40}, {Mountpoint: "/data", Percent: 70}},
		Load:   [3]float64{1.5, 1, 1},
	}
}

func TestMinuteAveraging(t *testing.T) {
	s := New("", FreeRetention)
	base := time.Now().Truncate(time.Minute).Add(-2 * time.Minute)
	for i := 0; i < 60; i++ {
		s.Add(snap(base.Add(time.Duration(i)*time.Second), 10, 50))
	}
	s.Add(snap(base.Add(30*time.Second), 30, 50)) // still minute 1
	if got := len(s.Since(time.Hour)); got != 0 {
		t.Fatalf("points before the minute closes = %d, want 0", got)
	}
	s.Add(snap(base.Add(time.Minute), 0, 0)) // opens minute 2, closes minute 1

	pts := s.Since(time.Hour)
	if len(pts) != 1 {
		t.Fatalf("points = %d, want 1", len(pts))
	}
	p := pts[0]
	if p.T != base.Unix() {
		t.Errorf("T = %d, want %d", p.T, base.Unix())
	}
	wantCPU := float32((60*10 + 30) / 61.0)
	if p.CPU < wantCPU-0.01 || p.CPU > wantCPU+0.01 {
		t.Errorf("CPU = %v, want %v", p.CPU, wantCPU)
	}
	if p.Disk != 70 {
		t.Errorf("Disk = %v, want the fullest disk (70)", p.Disk)
	}
}

func TestRetentionIsEnforced(t *testing.T) {
	s := New("", FreeRetention)
	old := time.Now().Add(-8 * 24 * time.Hour).Truncate(time.Minute)
	s.Add(snap(old, 1, 1))
	s.Add(snap(old.Add(time.Minute), 1, 1)) // closes the 8-day-old minute → pruned
	if got := len(s.Since(30 * 24 * time.Hour)); got != 0 {
		t.Fatalf("points older than 7 days kept: %d", got)
	}
	if s.Since(30*24*time.Hour) == nil {
		t.Fatal("Since must return an empty slice, not nil (JSON [])")
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.json")
	s := New(path, FreeRetention)
	base := time.Now().Truncate(time.Minute).Add(-5 * time.Minute)
	for m := 0; m < 4; m++ {
		s.Add(snap(base.Add(time.Duration(m)*time.Minute), float64(m*10), 20))
	}
	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reloaded := New(path, FreeRetention)
	if err := reloaded.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := len(reloaded.Since(time.Hour)); got != 3 {
		t.Fatalf("reloaded points = %d, want 3 closed minutes", got)
	}
}
