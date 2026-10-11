package scanner

import (
	"fmt"
	"net"
	"sort"

	gnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/xytherion/core/pkg/metrics"
)

// ListeningPorts returns all TCP/UDP ports in LISTEN state with process info.
func ListeningPorts() []metrics.ListeningPort {
	pidName := map[int32]string{}
	if procs, err := process.Processes(); err == nil {
		for _, p := range procs {
			name, _ := p.Name()
			if name != "" {
				pidName[p.Pid] = name
			}
		}
	}

	seen := map[string]bool{}
	var out []metrics.ListeningPort

	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		conns, err := gnet.Connections(proto)
		if err != nil {
			continue
		}
		shortProto := "tcp"
		if proto == "udp" || proto == "udp6" {
			shortProto = "udp"
		}
		for _, c := range conns {
			if c.Status != "LISTEN" && shortProto == "tcp" {
				continue
			}
			port := int(c.Laddr.Port)
			if port == 0 {
				continue
			}
			key := fmt.Sprintf("%s:%d", shortProto, port)
			if seen[key] {
				continue
			}
			seen[key] = true

			bindAddr := c.Laddr.IP
			lp := metrics.ListeningPort{
				Port:       port,
				Proto:      shortProto,
				BindAddr:   bindAddr,
				PublicFace: isPublic(bindAddr),
				PID:        c.Pid,
			}
			if name, ok := pidName[c.Pid]; ok {
				lp.Process = name
			}
			if def, ok := knownPorts[port]; ok {
				lp.Service = def.service
				lp.Risk = string(def.risk)
			}
			out = append(out, lp)
		}
	}

	// Public-facing first, then by port number
	sort.Slice(out, func(i, j int) bool {
		if out[i].PublicFace != out[j].PublicFace {
			return out[i].PublicFace
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// isPublic returns true if the bind address is reachable from the network.
func isPublic(ipStr string) bool {
	if ipStr == "" || ipStr == "0.0.0.0" || ipStr == "::" || ipStr == "*" {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true // unknown form — assume public to be conservative
	}
	return !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsMulticast()
}
