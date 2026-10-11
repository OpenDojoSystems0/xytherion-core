package discovery

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"sync"
	"time"
)

const (
	broadcastPort  = 9002
	announceEvery  = 8 * time.Second
	expireAfter    = 30 * time.Second
	broadcastAddr  = "255.255.255.255"
	maxPacketBytes = 1024
	maxPeers       = 256
)

// Peer représente un agent découvert sur le LAN.
type Peer struct {
	AgentID  string    `json:"agent_id"`
	Hostname string    `json:"hostname"`
	Addr     string    `json:"addr"`
	Port     int       `json:"port"`
	OS       string    `json:"os"`
	SeenAt   time.Time `json:"seen_at"`
}

type announcePacket struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
	Port     int    `json:"port"`
	OS       string `json:"os"`
}

// Manager gère la découverte LAN par broadcast UDP.
type Manager struct {
	agentID  string
	hostname string
	port     int
	osName   string
	onChange func([]Peer)

	mu    sync.RWMutex
	peers map[string]*Peer // keyed by agent_id
}

// NewManager crée un nouveau Manager de découverte.
func NewManager(agentID, hostname string, port int, osName string, onChange func([]Peer)) *Manager {
	return &Manager{
		agentID:  agentID,
		hostname: hostname,
		port:     port,
		osName:   osName,
		onChange: onChange,
		peers:    make(map[string]*Peer),
	}
}

// Run démarre les 3 goroutines: listen, announceLoop, expireLoop.
// Run starts listening for peers. announce is false when this agent is not
// reachable from the network (no token): it then stays silent on the LAN.
func (m *Manager) Run(announce bool) {
	go m.listenLoop()
	if announce {
		go m.announceLoop()
	}
	go m.expireLoop()
}

// Peers retourne la liste courante des peers découverts.
func (m *Manager) Peers() []Peer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Peer, 0, len(m.peers))
	for _, p := range m.peers {
		out = append(out, *p)
	}
	return out
}

func (m *Manager) listenLoop() {
	addr := &net.UDPAddr{Port: broadcastPort, IP: net.IPv4zero}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		log.Printf("[discovery] listen error: %v", err)
		return
	}
	defer conn.Close()

	buf := make([]byte, maxPacketBytes)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("[discovery] read error: %v", err)
			continue
		}

		var pkt announcePacket
		if err := json.Unmarshal(buf[:n], &pkt); err != nil {
			log.Printf("[discovery] unmarshal error: %v", err)
			continue
		}

		// Ignore own broadcasts and invalid packets
		if pkt.AgentID == m.agentID {
			continue
		}
		if len(pkt.AgentID) == 0 || len(pkt.AgentID) > 128 ||
			len(pkt.Hostname) > 255 || len(pkt.OS) > 32 ||
			pkt.Port < 1 || pkt.Port > 65535 {
			continue
		}

		peer := &Peer{
			AgentID:  pkt.AgentID,
			Hostname: pkt.Hostname,
			Addr:     src.IP.String(),
			Port:     pkt.Port,
			OS:       pkt.OS,
			SeenAt:   time.Now(),
		}

		m.mu.Lock()
		if _, exists := m.peers[pkt.AgentID]; !exists && len(m.peers) >= maxPeers {
			m.mu.Unlock()
			continue
		}
		m.peers[pkt.AgentID] = peer
		snapshot := m.snapshot()
		m.mu.Unlock()

		if m.onChange != nil {
			m.onChange(snapshot)
		}
	}
}

func (m *Manager) announceLoop() {
	m.sendAnnounce()
	ticker := time.NewTicker(announceEvery)
	defer ticker.Stop()
	for range ticker.C {
		m.sendAnnounce()
	}
}

func (m *Manager) sendAnnounce() {
	pkt := announcePacket{
		AgentID:  m.agentID,
		Hostname: m.hostname,
		Port:     m.port,
		OS:       m.osName,
	}
	data, err := json.Marshal(pkt)
	if err != nil {
		log.Printf("[discovery] marshal error: %v", err)
		return
	}

	addr := &net.UDPAddr{
		IP:   net.ParseIP(broadcastAddr),
		Port: broadcastPort,
	}
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		log.Printf("[discovery] dial error: %v", err)
		return
	}
	defer conn.Close()

	if _, err := conn.Write(data); err != nil {
		log.Printf("[discovery] write error: %v", err)
	}
}

func (m *Manager) expireLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		changed := false

		m.mu.Lock()
		for id, p := range m.peers {
			if now.Sub(p.SeenAt) > expireAfter {
				delete(m.peers, id)
				changed = true
			}
		}
		var snapshot []Peer
		if changed {
			snapshot = m.snapshot()
		}
		m.mu.Unlock()

		if changed && m.onChange != nil {
			m.onChange(snapshot)
		}
	}
}

// snapshot doit être appelé avec le mutex tenu en écriture ou lecture.
func (m *Manager) snapshot() []Peer {
	out := make([]Peer, 0, len(m.peers))
	for _, p := range m.peers {
		out = append(out, *p)
	}
	return out
}
