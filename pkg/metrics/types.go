package metrics

import "time"

type Snapshot struct {
	AgentID  string     `json:"agent_id"`
	Hostname string     `json:"hostname"`
	OS       string     `json:"os"`
	Arch     string     `json:"arch"`
	Time     time.Time  `json:"time"`
	CPU      CPUInfo    `json:"cpu"`
	Memory   MemInfo    `json:"memory"`
	Disk     []DiskInfo `json:"disk"`
	DiskIO   []DiskIO   `json:"disk_io,omitempty"`
	Net      NetInfo    `json:"net"`
	NetIO    NetIO      `json:"net_io"`
	Conns    []ConnInfo `json:"connections,omitempty"`
	Load     [3]float64 `json:"load"`
	Uptime   uint64     `json:"uptime"`
	Procs    []Process  `json:"procs,omitempty"`
}

type CPUInfo struct {
	Percent float64   `json:"percent"`
	PerCore []float64 `json:"per_core"`
	Cores   int       `json:"cores"`
}

type MemInfo struct {
	Total     uint64  `json:"total"`
	Used      uint64  `json:"used"`
	Available uint64  `json:"available"`
	Cached    uint64  `json:"cached"`
	Percent   float64 `json:"percent"`
	SwapTotal uint64  `json:"swap_total"`
	SwapUsed  uint64  `json:"swap_used"`
}

type DiskInfo struct {
	Device     string  `json:"device"`
	Mountpoint string  `json:"mountpoint"`
	Total      uint64  `json:"total"`
	Used       uint64  `json:"used"`
	Free       uint64  `json:"free"`
	Percent    float64 `json:"percent"`
}

type DiskIO struct {
	Name      string  `json:"name"`
	ReadMBs   float64 `json:"read_mb_s"`
	WriteMBs  float64 `json:"write_mb_s"`
	ReadIOPS  float64 `json:"read_iops"`
	WriteIOPS float64 `json:"write_iops"`
}

type NetInfo struct {
	BytesSent   uint64 `json:"bytes_sent"`
	BytesRecv   uint64 `json:"bytes_recv"`
	PacketsSent uint64 `json:"packets_sent"`
	PacketsRecv uint64 `json:"packets_recv"`
}

type NetIO struct {
	SendMBs float64 `json:"send_mb_s"`
	RecvMBs float64 `json:"recv_mb_s"`
}

type ConnInfo struct {
	Local  string `json:"local"`
	Remote string `json:"remote"`
	State  string `json:"state"`
	PID    int32  `json:"pid"`
}

type Process struct {
	PID    int32   `json:"pid"`
	Name   string  `json:"name"`
	CPU    float64 `json:"cpu"`
	Memory float32 `json:"memory"`
}

/* ── Alerts ────────────────────────────────────────────────────── */

type AlertSeverity string

const (
	AlertWarning  AlertSeverity = "warning"
	AlertCritical AlertSeverity = "critical"
)

type Alert struct {
	ID        string        `json:"id"`
	Metric    string        `json:"metric"`
	Message   string        `json:"message"`
	Value     float64       `json:"value"`
	Threshold float64       `json:"threshold"`
	Severity  AlertSeverity `json:"severity"`
	Active    bool          `json:"active"`
	FiredAt   time.Time     `json:"fired_at"`
	ClearedAt *time.Time    `json:"cleared_at,omitempty"`
}

/* ── Security scanner ──────────────────────────────────────────── */

type RiskLevel string

const (
	RiskInfo     RiskLevel = "info"
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

type PortResult struct {
	Port    int       `json:"port"`
	Service string    `json:"service"`
	Risk    RiskLevel `json:"risk"`
	Open    bool      `json:"open"`
	Note    string    `json:"note,omitempty"`
}

type ListeningPort struct {
	Port       int    `json:"port"`
	Proto      string `json:"proto"`
	BindAddr   string `json:"bind_addr"`
	PublicFace bool   `json:"public_face"` // true = accessible depuis le réseau
	PID        int32  `json:"pid"`
	Process    string `json:"process"`
	Service    string `json:"service,omitempty"`
	Risk       string `json:"risk,omitempty"`
}

type ScanResult struct {
	Ports      []PortResult `json:"ports"`
	ScannedAt  time.Time    `json:"scanned_at"`
	DurationMS int64        `json:"duration_ms"`
}

/* ── HTTP monitor ──────────────────────────────────────────────── */

type HTTPCheck struct {
	URL       string    `json:"url"`
	Status    int       `json:"status"`
	LatencyMS int64     `json:"latency_ms"`
	Up        bool      `json:"up"`
	SSLDays   *int      `json:"ssl_days,omitempty"`
	Error     string    `json:"error,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

/* ── SSH audit ─────────────────────────────────────────────────── */

type SSHLogin struct {
	User    string    `json:"user"`
	From    string    `json:"from"`
	Time    time.Time `json:"time"`
	Success bool      `json:"success"`
	TTY     string    `json:"tty,omitempty"`
}

/* ── Process fingerprint ───────────────────────────────────────── */

type ProcAnomaly struct {
	Name    string  `json:"name"`
	PID     int32   `json:"pid"`
	Score   float64 `json:"score"`
	CPU     float64 `json:"cpu"`
	MemPct  float32 `json:"mem_pct"`
	MeanCPU float64 `json:"mean_cpu"`
	MeanMem float32 `json:"mean_mem"`
}

/* ── Firewall ──────────────────────────────────────────────────── */

type FirewallStatus struct {
	Enabled bool   `json:"enabled"`
	Engine  string `json:"engine"`
	Rules   int    `json:"rules"`
	Details string `json:"details"`
}
