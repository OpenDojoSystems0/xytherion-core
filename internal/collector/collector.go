package collector

import (
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	gnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"

	"github.com/xytherion/core/pkg/metrics"
)

// prev holds the last-tick raw counters for delta calculations.
var prev struct {
	mu      sync.Mutex
	netSent uint64
	netRecv uint64
	diskIO  map[string]disk.IOCountersStat
	t       time.Time
}

var virtualFS = map[string]bool{
	"devfs": true, "tmpfs": true, "proc": true, "sysfs": true,
	"cgroup": true, "cgroup2": true, "overlay": true, "nsfs": true,
	"autofs": true, "squashfs": true, "devtmpfs": true, "efivarfs": true,
	"tracefs": true, "debugfs": true, "securityfs": true, "pstore": true,
	"bpf": true, "hugetlbfs": true, "mqueue": true, "configfs": true,
	"fusectl": true, "binfmt_misc": true, "ramfs": true, "rpc_pipefs": true,
	"nfsd": true, "fuse.lxcfs": true, "fuse.snapfuse": true, "fuse.portal": true,
}

// skipMount hides OS plumbing that would only duplicate the main disk:
// macOS sealed-system sub-volumes and the Recovery volume.
func skipMount(mountpoint string) bool {
	if runtime.GOOS == "darwin" {
		return strings.HasPrefix(mountpoint, "/System/Volumes/") || mountpoint == "/Volumes/Recovery"
	}
	return strings.HasPrefix(mountpoint, "/snap/") || strings.HasPrefix(mountpoint, "/boot/efi")
}

func Collect(agentID string) (*metrics.Snapshot, error) {
	hostname, _ := os.Hostname()
	snap := &metrics.Snapshot{
		AgentID:  agentID,
		Hostname: hostname,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Time:     time.Now(),
	}

	// CPU
	if percents, err := cpu.Percent(100*time.Millisecond, true); err == nil && len(percents) > 0 {
		var total float64
		for _, p := range percents {
			total += p
		}
		snap.CPU.Percent = total / float64(len(percents))
		snap.CPU.PerCore = percents
		snap.CPU.Cores = len(percents)
	}

	// Memory
	if vm, err := mem.VirtualMemory(); err == nil {
		snap.Memory.Total = vm.Total
		snap.Memory.Used = vm.Used
		snap.Memory.Available = vm.Available
		snap.Memory.Cached = vm.Cached
		snap.Memory.Percent = vm.UsedPercent
	}
	if sw, err := mem.SwapMemory(); err == nil {
		snap.Memory.SwapTotal = sw.Total
		snap.Memory.SwapUsed = sw.Used
	}

	// Disk usage (skip virtual filesystems)
	if parts, err := disk.Partitions(false); err == nil {
		for _, p := range parts {
			if virtualFS[p.Fstype] || skipMount(p.Mountpoint) {
				continue
			}
			usage, err := disk.Usage(p.Mountpoint)
			if err != nil || usage.Total == 0 {
				continue
			}
			snap.Disk = append(snap.Disk, metrics.DiskInfo{
				Device:     p.Device,
				Mountpoint: p.Mountpoint,
				Total:      usage.Total,
				Used:       usage.Used,
				Free:       usage.Free,
				Percent:    usage.UsedPercent,
			})
		}
	}

	// Fetch IO counters before acquiring the lock to minimise lock duration.
	now := time.Now()
	diskCounters, diskErr := disk.IOCounters()
	var netSnap *gnet.IOCountersStat
	if ctrs, err := gnet.IOCounters(false); err == nil && len(ctrs) > 0 {
		c := ctrs[0]
		netSnap = &c
		snap.Net.BytesSent = c.BytesSent
		snap.Net.BytesRecv = c.BytesRecv
		snap.Net.PacketsSent = c.PacketsSent
		snap.Net.PacketsRecv = c.PacketsRecv
	}

	prev.mu.Lock()
	dt := now.Sub(prev.t).Seconds()

	// Disk I/O rates — guard against uint64 underflow on counter reset/reboot.
	if diskErr == nil && dt > 0 && prev.diskIO != nil {
		for name, cur := range diskCounters {
			if p, ok := prev.diskIO[name]; ok {
				if cur.ReadBytes >= p.ReadBytes && cur.WriteBytes >= p.WriteBytes &&
					cur.ReadCount >= p.ReadCount && cur.WriteCount >= p.WriteCount {
					snap.DiskIO = append(snap.DiskIO, metrics.DiskIO{
						Name:      name,
						ReadMBs:   float64(cur.ReadBytes-p.ReadBytes) / dt / 1e6,
						WriteMBs:  float64(cur.WriteBytes-p.WriteBytes) / dt / 1e6,
						ReadIOPS:  float64(cur.ReadCount-p.ReadCount) / dt,
						WriteIOPS: float64(cur.WriteCount-p.WriteCount) / dt,
					})
				}
			}
		}
	}
	if diskErr == nil {
		prev.diskIO = diskCounters
	}

	// Network rates — same underflow guard; prev.t updated unconditionally so
	// disk rates are never computed with a stale dt when network collection fails.
	if netSnap != nil && dt > 0 && prev.t != (time.Time{}) {
		if netSnap.BytesSent >= prev.netSent {
			snap.NetIO.SendMBs = float64(netSnap.BytesSent-prev.netSent) / dt / 1e6
		}
		if netSnap.BytesRecv >= prev.netRecv {
			snap.NetIO.RecvMBs = float64(netSnap.BytesRecv-prev.netRecv) / dt / 1e6
		}
	}
	if netSnap != nil {
		prev.netSent = netSnap.BytesSent
		prev.netRecv = netSnap.BytesRecv
	}
	prev.t = now // always advance — disk dt is correct even when network fails
	prev.mu.Unlock()

	// Active TCP connections (established only, limit 50)
	if conns, err := gnet.Connections("tcp"); err == nil {
		for _, c := range conns {
			if c.Status != "ESTABLISHED" {
				continue
			}
			snap.Conns = append(snap.Conns, metrics.ConnInfo{
				Local:  c.Laddr.IP + ":" + itoa(c.Laddr.Port),
				Remote: c.Raddr.IP + ":" + itoa(c.Raddr.Port),
				State:  c.Status,
				PID:    c.Pid,
			})
			if len(snap.Conns) >= 50 {
				break
			}
		}
	}

	// Load
	if avg, err := load.Avg(); err == nil {
		snap.Load = [3]float64{avg.Load1, avg.Load5, avg.Load15}
	}

	// Uptime
	if up, err := host.Uptime(); err == nil {
		snap.Uptime = up
	}

	// Top processes by CPU
	if procs, err := process.Processes(); err == nil {
		type entry struct {
			pid  int32
			name string
			cpu  float64
			mem  float32
		}
		var entries []entry
		for _, p := range procs {
			name, _ := p.Name()
			cpuPct, _ := p.CPUPercent()
			memPct, _ := p.MemoryPercent()
			if name == "" {
				continue
			}
			entries = append(entries, entry{p.Pid, name, cpuPct, memPct})
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].cpu > entries[j].cpu })
		if len(entries) > 10 {
			entries = entries[:10]
		}
		for _, e := range entries {
			snap.Procs = append(snap.Procs, metrics.Process{
				PID: e.pid, Name: e.name, CPU: e.cpu, Memory: e.mem,
			})
		}
	}

	return snap, nil
}

func itoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	b := make([]byte, 0, 6)
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
